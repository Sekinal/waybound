//! Biomechanical pointer motion, click targeting, typing cadence, and scroll planning.
//!
//! Uses a Flash & Hogan minimum-jerk velocity profile with Fitts's law duration
//! scaling and bounded stochasticity.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::input::Point;
use crate::locator::Bounds;

const MAX_STEPS: u64 = 10_000;
static SEED_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Lightweight, seedable `SplitMix64` PRNG for reproducible tests and natural
/// motor-control variation without external crate dependencies.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a deterministic PRNG from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Creates a PRNG seeded from the system clock mixed with an atomic counter.
    #[must_use]
    pub fn from_entropy() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x9E37_79B9_7F4A_7C15, |d| {
                u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(0)
            });
        let seq = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self::new(nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    /// Returns the next pseudorandom `u64`.
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a uniform float in `[0.0, 1.0)`.
    #[allow(clippy::cast_precision_loss)]
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64))
    }

    /// Returns a uniform float in `[min, max]`.
    pub fn range_f64(&mut self, min: f64, max: f64) -> f64 {
        let lo = min.min(max);
        let hi = min.max(max);
        (hi - lo).mul_add(self.next_f64(), lo)
    }

    /// Returns a uniform integer in `[min, max]` (inclusive).
    pub const fn range_u64(&mut self, min: u64, max: u64) -> u64 {
        let lo = if min <= max { min } else { max };
        let hi = if min <= max { max } else { min };
        let span = hi.saturating_sub(lo).saturating_add(1);
        if span == 0 {
            return lo;
        }
        lo.saturating_add(self.next_u64() % span)
    }
}

/// A single timed waypoint along a pointer trajectory.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MotionStep {
    /// Target pointer position at this step.
    pub point: Point,
    /// Delay to wait before emitting this step.
    pub delay: Duration,
}

/// A single impulse in an inertial scroll burst.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScrollStep {
    /// Horizontal pixel delta for this impulse.
    pub delta_x: f64,
    /// Vertical pixel delta for this impulse.
    pub delta_y: f64,
    /// Delay to wait before emitting this impulse.
    pub delay: Duration,
}

/// Configuration controlling pointer trajectory generation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MotionConfig {
    /// Sampling interval between pointer move events in milliseconds (e.g., 8ms ≈ 125Hz).
    pub step_interval_ms: u64,
    /// Minimum total movement duration in milliseconds.
    pub min_duration_ms: u64,
    /// Maximum total movement duration in milliseconds.
    pub max_duration_ms: u64,
    /// Peak lateral arc offset as a fraction of total path distance (e.g., `0.035`).
    pub arc_ratio: f64,
}

impl Default for MotionConfig {
    fn default() -> Self {
        Self {
            step_interval_ms: 8,
            min_duration_ms: 90,
            max_duration_ms: 650,
            arc_ratio: 0.035,
        }
    }
}

/// Evaluates the normalized minimum-jerk progress $s(\tau) = 10\tau^3 - 15\tau^4 + 6\tau^5$
/// for $\tau \in [0, 1]$, which starts and ends with zero velocity and zero acceleration.
#[must_use]
pub fn minimum_jerk(tau: f64) -> f64 {
    let t = tau.clamp(0.0, 1.0);
    let t2 = t * t;
    let t3 = t2 * t;
    t3 * t.mul_add(6.0_f64.mul_add(t, -15.0), 10.0)
}

/// Picks a natural click target inside the inner 60% of `bounds` using a
/// triangular (center-biased) distribution so clicks avoid exact mathematical dead-center.
#[must_use]
pub fn pick_click_point(bounds: Bounds, rng: &mut SplitMix64) -> Point {
    // Triangular distribution in [-0.3, +0.3] around 0.5 => [0.2, 0.8] of width/height.
    let u_x = 0.3 * (rng.next_f64() - rng.next_f64());
    let u_y = 0.3 * (rng.next_f64() - rng.next_f64());
    Point {
        x: bounds.width.mul_add(0.5 + u_x, bounds.x),
        y: bounds.height.mul_add(0.5 + u_y, bounds.y),
    }
}

/// Returns a brief natural hover pause (`35..95ms`) after arriving at a target before clicking.
#[must_use]
pub const fn hover_pause_before_click(rng: &mut SplitMix64) -> Duration {
    Duration::from_millis(rng.range_u64(35, 95))
}

/// Returns a natural mouse-down dwell duration (`55..115ms`) between press and release.
#[must_use]
pub const fn mouse_hold_ms(rng: &mut SplitMix64) -> u64 {
    rng.range_u64(55, 115)
}

/// Returns a natural key-down dwell duration (`45..110ms`) between press and release.
#[must_use]
pub const fn key_hold_ms(rng: &mut SplitMix64) -> u64 {
    rng.range_u64(45, 110)
}

/// Returns a non-uniform inter-keystroke delay (`35..125ms`, slightly longer on spaces/punctuation).
#[must_use]
pub const fn key_delay(ch: char, rng: &mut SplitMix64) -> Duration {
    let base = rng.range_u64(35, 115);
    let extra = if ch == ' ' || ch.is_ascii_punctuation() {
        rng.range_u64(15, 65)
    } else {
        0
    };
    Duration::from_millis(base + extra)
}

/// Generates a smooth minimum-jerk pointer trajectory from `start` to `end`.
///
/// The `arc_sign` parameter (`+1.0`, `-1.0`, or `0.0`) chooses which side of the chord
/// the gentle natural wrist arc bows toward (`0.0` produces a straight minimum-jerk path).
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn plan_pointer_path(
    start: Point,
    end: Point,
    arc_sign: f64,
    config: MotionConfig,
) -> Vec<MotionStep> {
    if !start.x.is_finite() || !start.y.is_finite() || !end.x.is_finite() || !end.y.is_finite() {
        return Vec::new();
    }

    let dx = end.x - start.x;
    let dy = end.y - start.y;
    let distance = dx.hypot(dy);

    if !distance.is_finite() || distance < 1.0 {
        return vec![MotionStep {
            point: end,
            delay: Duration::ZERO,
        }];
    }

    let min_ms = config.min_duration_ms.min(config.max_duration_ms) as f64;
    let max_ms = config.min_duration_ms.max(config.max_duration_ms) as f64;

    // Fitts's law inspired duration: ~110ms + 75ms * log2(1 + distance / 20).
    let raw_ms = 75.0_f64.mul_add((1.0 + distance / 20.0).log2(), 110.0);
    let total_ms = raw_ms.round().clamp(min_ms, max_ms) as u64;

    let interval = config.step_interval_ms.max(1);
    let steps = (total_ms / interval).clamp(2, MAX_STEPS);

    // Unit normal perpendicular to the chord for subtle natural arc curvature.
    let nx = -dy / distance;
    let ny = dx / distance;
    let safe_ratio = if config.arc_ratio.is_finite() {
        config.arc_ratio
    } else {
        0.0
    };
    let safe_sign = if !arc_sign.is_finite() || arc_sign == 0.0 {
        0.0
    } else {
        arc_sign.signum()
    };
    let peak_offset = distance * safe_ratio * safe_sign;

    let mut path = Vec::with_capacity(usize::try_from(steps).unwrap_or(64));
    for i in 1..=steps {
        let tau = i as f64 / steps as f64;
        let progress = minimum_jerk(tau);
        // The arc is a function of forward progress, not of time, so the path is a fixed
        // curve in space traversed with the minimum-jerk speed profile. Driving it by `tau`
        // makes the lateral offset grow linearly while forward progress is still ~0, so the
        // pointer would leave and arrive almost perpendicular to the direction of travel.
        let lateral = peak_offset * (std::f64::consts::PI * progress).sin();

        let point = if i == steps {
            end
        } else {
            Point {
                x: nx.mul_add(lateral, dx.mul_add(progress, start.x)),
                y: ny.mul_add(lateral, dy.mul_add(progress, start.y)),
            }
        };

        path.push(MotionStep {
            point,
            delay: Duration::from_millis(interval),
        });
    }

    path
}

/// Generates a stochastic minimum-jerk pointer trajectory with randomized arc direction,
/// curvature, subtle micro-jitter (vanishing at endpoints), and polling-interval jitter.
#[must_use]
pub fn plan_human_pointer_path(
    start: Point,
    end: Point,
    mut config: MotionConfig,
    rng: &mut SplitMix64,
) -> Vec<MotionStep> {
    let arc_sign = if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
    config.arc_ratio = rng.range_f64(0.015, 0.055);
    let mut path = plan_pointer_path(start, end, arc_sign, config);
    let len = path.len();
    if len <= 2 {
        return path;
    }

    for (idx, step) in path.iter_mut().enumerate() {
        if idx + 1 < len {
            let jitter_x = rng.range_f64(-0.6, 0.6);
            let jitter_y = rng.range_f64(-0.6, 0.6);
            step.point.x += jitter_x;
            step.point.y += jitter_y;
        }
        step.delay = Duration::from_millis(rng.range_u64(6, 11));
    }

    path
}

/// Breaks a scroll delta into 5–9 smooth ease-out inertial wheel impulses whose
/// total sum equals `(delta_x, delta_y)`.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn plan_scroll_burst(delta_x: f64, delta_y: f64, rng: &mut SplitMix64) -> Vec<ScrollStep> {
    if !delta_x.is_finite() || !delta_y.is_finite() {
        return Vec::new();
    }
    if delta_x.hypot(delta_y) < 40.0 {
        return vec![ScrollStep {
            delta_x,
            delta_y,
            delay: Duration::ZERO,
        }];
    }

    let count = usize::try_from(rng.range_u64(5, 9)).unwrap_or(6);
    let mut weights = Vec::with_capacity(count);
    let mut weight_sum = 0.0;
    for i in 0..count {
        // Ease-out weight curve (stronger initial flick, tapering tail).
        let t = (i as f64 + 1.0) / (count as f64 + 1.0);
        let w = t.mul_add(-0.75, 1.0).max(0.15);
        weights.push(w);
        weight_sum += w;
    }

    let mut steps = Vec::with_capacity(count);
    let mut acc_x = 0.0;
    let mut acc_y = 0.0;
    for (idx, w) in weights.into_iter().enumerate() {
        let (sx, sy) = if idx + 1 == count {
            (delta_x - acc_x, delta_y - acc_y)
        } else {
            let frac = w / weight_sum;
            let sx = delta_x * frac;
            let sy = delta_y * frac;
            acc_x += sx;
            acc_y += sy;
            (sx, sy)
        };
        steps.push(ScrollStep {
            delta_x: sx,
            delta_y: sy,
            delay: Duration::from_millis(rng.range_u64(14, 28)),
        });
    }

    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_jerk_respects_boundary_conditions() {
        assert!((minimum_jerk(0.0) - 0.0).abs() < f64::EPSILON);
        assert!((minimum_jerk(0.5) - 0.5).abs() < 1e-12);
        assert!((minimum_jerk(1.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn plan_pointer_path_starts_near_origin_and_lands_exact() {
        let start = Point { x: 10.0, y: 20.0 };
        let end = Point { x: 410.0, y: 320.0 };
        let path = plan_pointer_path(start, end, 1.0, MotionConfig::default());

        assert!(path.len() >= 10);
        assert_eq!(path.last().map(|s| s.point), Some(end));
    }

    #[test]
    fn plan_pointer_path_departs_and_arrives_along_the_chord() {
        // Horizontal move: forward is +x, lateral is y.
        let start = Point { x: 0.0, y: 0.0 };
        let end = Point { x: 800.0, y: 0.0 };
        let path = plan_pointer_path(start, end, 1.0, MotionConfig::default());
        assert!(path.len() >= 10);

        // With arc_ratio r the path is y = r*d*sin(pi*x/d), whose slope never exceeds pi*r.
        let max_slope = std::f64::consts::PI * MotionConfig::default().arc_ratio * 1.05;
        for step in &path[..path.len() - 1] {
            let forward = step.point.x;
            let lateral = step.point.y.abs();
            assert!(
                lateral <= forward.mul_add(max_slope, 1e-9),
                "lateral {lateral} exceeds forward {forward} * {max_slope}"
            );
            let remaining = end.x - forward;
            assert!(
                lateral <= remaining.mul_add(max_slope, 1e-9),
                "lateral {lateral} exceeds remaining {remaining} * {max_slope}"
            );
        }
    }

    #[test]
    fn plan_pointer_path_handles_inverted_durations_and_non_finite_inputs() {
        let inverted = MotionConfig {
            min_duration_ms: 500,
            max_duration_ms: 100,
            ..MotionConfig::default()
        };
        let path = plan_pointer_path(
            Point { x: 0.0, y: 0.0 },
            Point { x: 200.0, y: 0.0 },
            0.0,
            inverted,
        );
        assert_ne!(path.len(), 0);
        assert!(path.iter().all(|s| s.point.y.abs() < 1e-12));

        let bad = plan_pointer_path(
            Point {
                x: f64::NAN,
                y: 0.0,
            },
            Point { x: 100.0, y: 0.0 },
            1.0,
            MotionConfig::default(),
        );
        assert_eq!(bad.len(), 0);
    }

    #[test]
    fn pick_click_point_stays_within_inner_bounds() {
        let mut rng = SplitMix64::new(42);
        let bounds = Bounds {
            x: 100.0,
            y: 200.0,
            width: 100.0,
            height: 50.0,
        };
        for _ in 0..50 {
            let p = pick_click_point(bounds, &mut rng);
            assert!(p.x >= 120.0 && p.x <= 180.0);
            assert!(p.y >= 210.0 && p.y <= 240.0);
        }
    }

    #[test]
    fn scroll_burst_preserves_total_delta() {
        let mut rng = SplitMix64::new(7);
        let steps = plan_scroll_burst(0.0, -300.0, &mut rng);
        assert!(steps.len() >= 5);
        let sum_y: f64 = steps.iter().map(|s| s.delta_y).sum();
        assert!((sum_y + 300.0).abs() < 1e-9);
    }
}
