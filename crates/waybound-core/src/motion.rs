//! Biomechanical pointer motion, click targeting, typing cadence, and scroll planning.
//!
//! Combines Plamondon's Sigma-Lognormal ($\Sigma\Lambda$) kinematic velocity profile,
//! directional Shannon Fitts's law duration scaling, Meyer's overlapping corrective
//! submovements, Ornstein-Uhlenbeck signal-dependent noise, speed-damped physiological
//! tremor, QWERTY bigram typing dynamics, and dual-mode inertial/detent scrolling —
//! all in pure `f64` with zero external dependencies.

use std::f64::consts::{PI, SQRT_2, TAU};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::input::Point;
use crate::locator::Bounds;

const MAX_STEPS: u64 = 10_000;
const SQRT_TAU: f64 = 2.506_628_274_631_000_5;
/// Lower lognormal quantile ($-3.0\sigma$, $q \approx 0.00135$) where observable motion begins.
const SIGMA_LN_Z_START: f64 = 3.0;
/// Upper lognormal quantile ($+2.15\sigma$, $q \approx 0.9842$) where the stroke settles.
const SIGMA_LN_Z_END: f64 = 2.15;

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

    /// Returns a standard normal variate via the Box-Muller transform.
    ///
    /// Clamps `u1 >= 1e-12` so `ln(u1)` is always finite.
    pub fn next_normal(&mut self) -> f64 {
        let u1 = self.next_f64().max(1e-12);
        let u2 = self.next_f64();
        (-2.0 * u1.ln()).sqrt() * (TAU * u2).cos()
    }

    /// Returns a lognormal variate with the given `median` ($e^\mu$) and log-space
    /// standard deviation `sigma`.
    ///
    /// Degenerate or non-finite inputs safely return `0.0` (if `median <= 0` or non-finite)
    /// or `median` (if `sigma <= 0` or non-finite).
    pub fn next_lognormal(&mut self, median: f64, sigma: f64) -> f64 {
        if !median.is_finite() || median <= 0.0 {
            return 0.0;
        }
        if !sigma.is_finite() || sigma <= 0.0 {
            return median;
        }
        let sample = median * (sigma * self.next_normal()).exp();
        if sample.is_finite() { sample } else { median }
    }

    /// Returns a lognormal variate with `median` and `sigma`, clamped to `[min, max]`.
    ///
    /// Handles inverted bounds (`min > max`) and non-finite or degenerate inputs safely.
    pub fn next_lognormal_clamped(&mut self, median: f64, sigma: f64, min: f64, max: f64) -> f64 {
        if !min.is_finite() || !max.is_finite() {
            return if median.is_finite() && median > 0.0 {
                median
            } else {
                0.0
            };
        }
        let lo = min.min(max);
        let hi = min.max(max);
        let sample = self.next_lognormal(median, sigma);
        if sample.is_finite() {
            sample.clamp(lo, hi)
        } else {
            hi
        }
    }
}

/// Evaluates the complementary error function $\operatorname{erfc}(x)$ using the
/// Abramowitz & Stegun 7.1.26 rational approximation (max error $< 1.5 \times 10^{-7}$).
#[must_use]
pub fn erfc_approx(x: f64) -> f64 {
    if x.is_nan() {
        return f64::NAN;
    }
    if x.is_infinite() {
        return if x.is_sign_positive() { 0.0 } else { 2.0 };
    }
    let ax = x.abs();
    let t = 1.0 / 0.327_591_1_f64.mul_add(ax, 1.0);
    let poly = t.mul_add(
        t.mul_add(
            t.mul_add(
                t.mul_add(1.061_405_429_f64.mul_add(t, -1.453_152_027), 1.421_413_741),
                -0.284_496_736,
            ),
            0.254_829_592,
        ),
        0.0,
    );
    let pos_erfc = (poly * (-ax * ax).exp()).clamp(0.0, 1.0);
    if x >= 0.0 {
        pos_erfc
    } else {
        (2.0 - pos_erfc).clamp(0.0, 2.0)
    }
}

/// Evaluates the Sigma-Lognormal cumulative progress
/// $s(t) = \frac{1}{2}\operatorname{erfc}\!\left(-\frac{\ln(t) - \mu}{\sigma\sqrt{2}}\right)$
/// in `[0.0, 1.0]`.
#[must_use]
pub fn sigma_lognormal_progress(t: f64, mu: f64, sigma: f64) -> f64 {
    if !mu.is_finite() || !sigma.is_finite() || sigma <= 0.0 || t.is_nan() {
        return 0.0;
    }
    if t <= 0.0 {
        return 0.0;
    }
    if t.is_infinite() {
        return 1.0;
    }
    let z = -(t.ln() - mu) / (sigma * SQRT_2);
    (0.5 * erfc_approx(z)).clamp(0.0, 1.0)
}

/// Evaluates a normalized Sigma-Lognormal stroke over `u` in `[0, 1]`, returning
/// `(progress, d_progress_du)` where `progress(0) == 0.0` and `progress(1) == 1.0`.
///
/// The internal lognormal window spans `[exp(-z_start * sigma), exp(z_end * sigma)]` so
/// peak velocity lands naturally around 32%–40% of stroke duration while both endpoints
/// have near-zero velocity.
fn normalized_sigma_lognormal(u: f64, sigma: f64) -> (f64, f64) {
    let u = u.clamp(0.0, 1.0);
    let s = sigma.clamp(0.12, 0.65);
    let t_start = (-SIGMA_LN_Z_START * s).exp();
    let t_end = (SIGMA_LN_Z_END * s).exp();
    let span = t_end - t_start;
    let cdf_start = sigma_lognormal_progress(t_start, 0.0, s);
    let cdf_end = sigma_lognormal_progress(t_end, 0.0, s);
    let cdf_span = (cdf_end - cdf_start).max(1e-9);

    if u <= 0.0 {
        return (0.0, 0.0);
    }
    if u >= 1.0 {
        return (1.0, 0.0);
    }

    let t = span.mul_add(u, t_start);
    let cdf = sigma_lognormal_progress(t, 0.0, s);
    let progress = ((cdf - cdf_start) / cdf_span).clamp(0.0, 1.0);

    let ln_t = t.ln();
    let pdf = (-(ln_t * ln_t) / (2.0 * s * s)).exp() / (t * s * SQRT_TAU);
    let speed = (pdf * span / cdf_span).max(0.0);
    (progress, speed)
}

/// Physical scroll device dynamics modeled for a session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScrollStyle {
    /// Smooth inertial trackpad/touch scrolling with exponential velocity decay.
    TrackpadInertial {
        /// Exponential decay constant in inverse seconds (typically `2.5..5.5`).
        damping: f64,
    },
    /// Discrete ratcheted mouse wheel emitting quantized physical detents.
    WheelDetent {
        /// Approximate pixel displacement per wheel detent notch (typically `95..125 px`).
        notch_px: f64,
    },
}

/// Persistent per-session biomechanical motor profile.
///
/// Sampled once per session via [`MotorProfile::sample`] so pointer kinematics,
/// polling cadence, targeting bias, typing rhythm, and scrolling physics remain
/// internally consistent across actions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MotorProfile {
    /// Fitts's law intercept $a$ in milliseconds (~95..145 ms).
    pub fitts_a_ms: f64,
    /// Fitts's law slope $b$ in milliseconds per bit (~95..140 ms/bit).
    pub fitts_b_ms: f64,
    /// Lognormal spread of movement duration around Fitts's law prediction (~0.10..0.18).
    pub duration_sigma: f64,
    /// Sigma-Lognormal shape parameter $\sigma$ controlling velocity asymmetry (~0.24..0.34).
    pub lognormal_sigma: f64,
    /// Hardware pointer polling interval in milliseconds (e.g., 8 ms [125 Hz] or 16 ms [60 Hz]).
    pub polling_interval_ms: u64,
    /// Standard deviation of OS/USB polling jitter in milliseconds (~0.5..1.5 ms).
    pub polling_jitter_ms: f64,
    /// Subtle signed preference for wrist-arc direction in `[-0.35, +0.35]`.
    pub arc_handedness_bias: f64,
    /// Multiplier applied to baseline wrist arc curvature (~0.75..1.30).
    pub arc_ratio_scale: f64,
    /// Tendency to produce Meyer's corrective submovements on medium/high-ID moves (~0.20..0.48).
    pub overshoot_tendency: f64,
    /// Ornstein-Uhlenbeck noise correlation time constant in milliseconds (~45..80 ms).
    pub ou_tau_ms: f64,
    /// Scale factor for Harris-Wolpert signal-dependent trajectory noise (~0.35..0.85).
    pub sdn_scale: f64,
    /// Physiological micro-tremor frequency in Hz (~8.5..11.5 Hz).
    pub tremor_freq_hz: f64,
    /// Peak speed-damped physiological micro-tremor amplitude in pixels (~0.12..0.32 px).
    pub tremor_amp_px: f64,
    /// Median pre-click hover settle pause in milliseconds (~45..85 ms).
    pub hover_pause_median_ms: f64,
    /// Median mouse-button hold duration in milliseconds (~68..105 ms).
    pub mouse_hold_median_ms: f64,
    /// Median inter-click gap for double-clicks in milliseconds (~95..145 ms).
    pub double_click_gap_median_ms: f64,
    /// Fraction of element size to shift clicks toward the approach entry edge (~0.08..0.18).
    pub click_entry_bias: f64,
    /// Probability of an actuation-induced micro-slip during a click (~0.25..0.40).
    pub click_slip_prob: f64,
    /// Median inter-keystroke interval (IKI) in milliseconds (~85..155 ms).
    pub typing_iki_median_ms: f64,
    /// Median key-down dwell duration in milliseconds (~72..108 ms).
    pub typing_hold_median_ms: f64,
    /// Median cognitive burst pause at word/clause boundaries in milliseconds (~45..110 ms).
    pub typing_word_pause_median_ms: f64,
    /// Probability of keystroke rollover overlap on alternating-hand transitions (~0.22..0.48).
    pub typing_rollover_ratio: f64,
    /// Physical scroll device style for this session.
    pub scroll_style: ScrollStyle,
    /// Median inter-burst reading/clutching pause during scrolling in milliseconds (~150..320 ms).
    pub reading_pause_median_ms: f64,
}

impl Default for MotorProfile {
    fn default() -> Self {
        Self {
            fitts_a_ms: 115.0,
            fitts_b_ms: 112.0,
            duration_sigma: 0.14,
            lognormal_sigma: 0.28,
            polling_interval_ms: 8,
            polling_jitter_ms: 0.9,
            arc_handedness_bias: 0.12,
            arc_ratio_scale: 1.0,
            overshoot_tendency: 0.34,
            ou_tau_ms: 60.0,
            sdn_scale: 0.55,
            tremor_freq_hz: 10.0,
            tremor_amp_px: 0.20,
            hover_pause_median_ms: 62.0,
            mouse_hold_median_ms: 84.0,
            double_click_gap_median_ms: 116.0,
            click_entry_bias: 0.12,
            click_slip_prob: 0.32,
            typing_iki_median_ms: 115.0,
            typing_hold_median_ms: 88.0,
            typing_word_pause_median_ms: 72.0,
            typing_rollover_ratio: 0.30,
            scroll_style: ScrollStyle::TrackpadInertial { damping: 3.8 },
            reading_pause_median_ms: 215.0,
        }
    }
}

impl MotorProfile {
    /// Samples a realistic, internally consistent biomechanical profile for a session.
    #[must_use]
    pub fn sample(rng: &mut SplitMix64) -> Self {
        let scroll_style = if rng.next_f64() < 0.55 {
            ScrollStyle::TrackpadInertial {
                damping: rng.range_f64(2.8, 5.2),
            }
        } else {
            ScrollStyle::WheelDetent {
                notch_px: rng.range_f64(95.0, 125.0),
            }
        };
        Self {
            fitts_a_ms: rng.range_f64(95.0, 145.0),
            fitts_b_ms: rng.range_f64(95.0, 140.0),
            duration_sigma: rng.range_f64(0.10, 0.18),
            lognormal_sigma: rng.range_f64(0.24, 0.34),
            polling_interval_ms: if rng.next_f64() < 0.65 { 8 } else { 16 },
            polling_jitter_ms: rng.range_f64(0.5, 1.5),
            arc_handedness_bias: rng.range_f64(-0.35, 0.35),
            arc_ratio_scale: rng.range_f64(0.75, 1.30),
            overshoot_tendency: rng.range_f64(0.20, 0.48),
            ou_tau_ms: rng.range_f64(45.0, 80.0),
            sdn_scale: rng.range_f64(0.35, 0.85),
            tremor_freq_hz: rng.range_f64(8.5, 11.5),
            tremor_amp_px: rng.range_f64(0.12, 0.32),
            hover_pause_median_ms: rng.range_f64(45.0, 85.0),
            mouse_hold_median_ms: rng.range_f64(68.0, 105.0),
            double_click_gap_median_ms: rng.range_f64(95.0, 145.0),
            click_entry_bias: rng.range_f64(0.08, 0.18),
            click_slip_prob: rng.range_f64(0.25, 0.40),
            typing_iki_median_ms: rng.range_f64(85.0, 155.0),
            typing_hold_median_ms: rng.range_f64(72.0, 108.0),
            typing_word_pause_median_ms: rng.range_f64(45.0, 110.0),
            typing_rollover_ratio: rng.range_f64(0.22, 0.48),
            scroll_style,
            reading_pause_median_ms: rng.range_f64(150.0, 320.0),
        }
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

/// A single impulse in an inertial or detented scroll burst.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScrollStep {
    /// Horizontal pixel delta for this impulse.
    pub delta_x: f64,
    /// Vertical pixel delta for this impulse.
    pub delta_y: f64,
    /// Delay to wait before emitting this impulse.
    pub delay: Duration,
}

/// A single planned keystroke with biomechanical dwell and post-keystroke delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeystrokeStep {
    /// Character to emit.
    pub ch: char,
    /// Key-down dwell duration in milliseconds.
    pub hold_ms: u64,
    /// Delay to wait after this keystroke before starting the next keystroke.
    pub delay_after: Duration,
}

/// Press or release phase for an event in a rollover typing timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    /// Key press (down) transition.
    Down,
    /// Key release (up) transition.
    Up,
}

/// A single timed key-down or key-up event in a biomechanical rollover typing schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyTimelineEvent {
    /// Character associated with this key transition.
    pub ch: char,
    /// Press or release action.
    pub action: KeyAction,
    /// Delay to wait before dispatching this event.
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

/// Picks a natural click target inside `bounds`, subtly biased toward the approach entry
/// edge when `start` lies outside `bounds` and the target is sufficiently wide or tall.
///
/// The returned point is strictly clamped inside `[0.15, 0.85]` of `bounds`.
#[must_use]
pub fn pick_click_point_from(
    start: Option<Point>,
    bounds: Bounds,
    profile: &MotorProfile,
    rng: &mut SplitMix64,
) -> Point {
    let mut shift_x = 0.0;
    let mut shift_y = 0.0;

    if let Some(origin) = start
        && origin.x.is_finite()
        && origin.y.is_finite()
        && bounds.x.is_finite()
        && bounds.y.is_finite()
        && bounds.width.is_finite()
        && bounds.height.is_finite()
        && bounds.width > 0.0
        && bounds.height > 0.0
    {
        let outside = origin.x < bounds.x
            || origin.x > bounds.x + bounds.width
            || origin.y < bounds.y
            || origin.y > bounds.y + bounds.height;
        if outside {
            let (cx, cy) = bounds.center();
            let dx = origin.x - cx;
            let dy = origin.y - cy;
            let dist = dx.hypot(dy);
            if dist.is_finite() && dist > 1e-3 {
                let bias = if profile.click_entry_bias.is_finite() {
                    profile.click_entry_bias.clamp(0.0, 0.22)
                } else {
                    0.12
                };
                if bounds.width > 30.0 {
                    shift_x = (bias * (dx / dist)).clamp(-0.18, 0.18);
                }
                if bounds.height > 30.0 {
                    shift_y = (bias * (dy / dist)).clamp(-0.18, 0.18);
                }
            }
        }
    }

    let noise_x = (rng.next_normal() * 0.12).clamp(-0.32, 0.32);
    let noise_y = (rng.next_normal() * 0.12).clamp(-0.32, 0.32);
    let frac_x = (0.5 + shift_x + noise_x).clamp(0.15, 0.85);
    let frac_y = (0.5 + shift_y + noise_y).clamp(0.15, 0.85);

    Point {
        x: bounds.width.mul_add(frac_x, bounds.x),
        y: bounds.height.mul_add(frac_y, bounds.y),
    }
}

/// Returns a small actuation-induced pointer micro-slip (`0.5..1.8 px`) during a click.
///
/// Fires with probability `profile.click_slip_prob`, clamped safely inside `bounds`
/// (with at least a 2 px margin from each edge) when bounds are provided.
#[must_use]
pub fn plan_click_slip(
    point: Point,
    bounds: Option<Bounds>,
    profile: &MotorProfile,
    rng: &mut SplitMix64,
) -> Option<Point> {
    if !point.x.is_finite() || !point.y.is_finite() {
        return None;
    }
    let prob = if profile.click_slip_prob.is_finite() {
        profile.click_slip_prob.clamp(0.0, 1.0)
    } else {
        0.0
    };
    if rng.next_f64() >= prob {
        return None;
    }

    let angle = rng.range_f64(0.0, TAU);
    let radius = rng.range_f64(0.5, 1.8);
    let mut slipped = Point {
        x: radius.mul_add(angle.cos(), point.x),
        y: radius.mul_add(angle.sin(), point.y),
    };

    if let Some(b) = bounds {
        if !b.x.is_finite()
            || !b.y.is_finite()
            || !b.width.is_finite()
            || !b.height.is_finite()
            || b.width <= 4.0
            || b.height <= 4.0
        {
            return None;
        }
        slipped.x = slipped.x.clamp(b.x + 2.0, b.x + b.width - 2.0);
        slipped.y = slipped.y.clamp(b.y + 2.0, b.y + b.height - 2.0);
        if (slipped.x - point.x).hypot(slipped.y - point.y) < 0.25 {
            return None;
        }
    }

    Some(slipped)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn sample_ms(
    rng: &mut SplitMix64,
    median: f64,
    sigma: f64,
    min_ms: f64,
    max_ms: f64,
    fallback_median: f64,
) -> u64 {
    let safe_median = if median.is_finite() && median > 0.0 {
        median
    } else {
        fallback_median
    };
    rng.next_lognormal_clamped(safe_median, sigma, min_ms, max_ms)
        .round()
        .max(0.0) as u64
}

/// Returns a right-skewed lognormal pre-click hover pause sampled from `profile`.
#[must_use]
pub fn hover_pause_for(profile: &MotorProfile, rng: &mut SplitMix64) -> Duration {
    Duration::from_millis(sample_ms(
        rng,
        profile.hover_pause_median_ms,
        0.32,
        20.0,
        260.0,
        62.0,
    ))
}

/// Returns a right-skewed lognormal mouse-button hold duration in milliseconds from `profile`.
#[must_use]
pub fn mouse_hold_for(profile: &MotorProfile, rng: &mut SplitMix64) -> u64 {
    sample_ms(rng, profile.mouse_hold_median_ms, 0.24, 35.0, 220.0, 84.0)
}

/// Returns a right-skewed lognormal inter-click gap for double-clicks from `profile`.
#[must_use]
pub fn double_click_gap_for(profile: &MotorProfile, rng: &mut SplitMix64) -> Duration {
    Duration::from_millis(sample_ms(
        rng,
        profile.double_click_gap_median_ms,
        0.22,
        65.0,
        210.0,
        116.0,
    ))
}

/// Returns a right-skewed lognormal key-down dwell duration in milliseconds from `profile`.
#[must_use]
pub fn key_hold_for(profile: &MotorProfile, rng: &mut SplitMix64) -> u64 {
    sample_ms(rng, profile.typing_hold_median_ms, 0.24, 30.0, 210.0, 88.0)
}

/// Returns a right-skewed lognormal UI transition pause scaled around `base_ms` by `profile`.
#[must_use]
pub fn action_pause_for(profile: &MotorProfile, base_ms: f64, rng: &mut SplitMix64) -> Duration {
    if !base_ms.is_finite() || base_ms <= 0.0 {
        return Duration::ZERO;
    }
    let tempo = if profile.hover_pause_median_ms.is_finite() && profile.hover_pause_median_ms > 0.0
    {
        (profile.hover_pause_median_ms / 62.0).clamp(0.75, 1.35)
    } else {
        1.0
    };
    let median = base_ms * tempo;
    let lo = (base_ms * 0.45).max(10.0);
    let hi = (base_ms * 2.4).max(lo);
    Duration::from_millis(sample_ms(rng, median, 0.28, lo, hi, base_ms))
}

/// Returns a right-skewed lognormal inter-scroll reading/clutching pause from `profile`.
#[must_use]
pub fn reading_pause_for(profile: &MotorProfile, rng: &mut SplitMix64) -> Duration {
    Duration::from_millis(sample_ms(
        rng,
        profile.reading_pause_median_ms,
        0.36,
        90.0,
        650.0,
        215.0,
    ))
}

/// Returns a brief natural right-skewed hover pause after arriving at a target before clicking.
#[must_use]
pub fn hover_pause_before_click(rng: &mut SplitMix64) -> Duration {
    hover_pause_for(&MotorProfile::default(), rng)
}

/// Returns a natural right-skewed mouse-down dwell duration in milliseconds.
#[must_use]
pub fn mouse_hold_ms(rng: &mut SplitMix64) -> u64 {
    mouse_hold_for(&MotorProfile::default(), rng)
}

/// Returns a natural right-skewed key-down dwell duration in milliseconds.
#[must_use]
pub fn key_hold_ms(rng: &mut SplitMix64) -> u64 {
    key_hold_for(&MotorProfile::default(), rng)
}

/// Returns a right-skewed inter-keystroke delay (longer on spaces and punctuation).
#[must_use]
pub fn key_delay(ch: char, rng: &mut SplitMix64) -> Duration {
    let base = sample_ms(rng, 95.0, 0.35, 30.0, 320.0, 95.0);
    let extra = if ch == ' ' || ch.is_ascii_punctuation() {
        sample_ms(rng, 55.0, 0.40, 15.0, 220.0, 55.0)
    } else {
        0
    };
    Duration::from_millis(base.saturating_add(extra))
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
        let lateral = peak_offset * (PI * progress).sin();

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

/// Evaluates an asymmetric smooth lateral arc $s^\alpha (1 - s)^\beta$ normalized so its
/// peak is `1.0` and both endpoints vanish cleanly.
fn asymmetric_arc(progress: f64, alpha: f64, beta: f64) -> f64 {
    let s = progress.clamp(0.0, 1.0);
    if s <= 0.0 || s >= 1.0 {
        return 0.0;
    }
    let s_peak = alpha / (alpha + beta);
    let peak = (s_peak.powf(alpha) * (1.0 - s_peak).powf(beta)).max(1e-9);
    (s.powf(alpha) * (1.0 - s).powf(beta) / peak).clamp(0.0, 1.0)
}

/// Asymmetric lateral arc parameters for a pointer stroke.
#[derive(Clone, Copy)]
struct ArcParams {
    peak_offset: f64,
    alpha: f64,
    beta: f64,
}

/// Displacement and instantaneous speed evaluated along a single stroke.
#[derive(Clone, Copy, Default)]
struct StrokeEval {
    offset_x: f64,
    offset_y: f64,
    speed: f64,
}

/// Parameters for a single Sigma-Lognormal vector stroke.
struct StrokeSpec {
    dx: f64,
    dy: f64,
    nx: f64,
    ny: f64,
    dist: f64,
    arc: ArcParams,
    t0_ms: f64,
    duration_ms: f64,
    sigma: f64,
}

impl StrokeSpec {
    fn between(
        from: Point,
        to: Point,
        arc: ArcParams,
        t0_ms: f64,
        duration_ms: f64,
        sigma: f64,
    ) -> Self {
        let dx = to.x - from.x;
        let dy = to.y - from.y;
        let dist = dx.hypot(dy);
        let (nx, ny) = if dist > 1e-6 {
            (-dy / dist, dx / dist)
        } else {
            (0.0, 0.0)
        };
        Self {
            dx,
            dy,
            nx,
            ny,
            dist,
            arc,
            t0_ms,
            duration_ms: duration_ms.max(1.0),
            sigma,
        }
    }

    /// Evaluates displacement and instantaneous speed magnitude (px/ms) at `t_ms`.
    fn eval(&self, t_ms: f64) -> StrokeEval {
        if t_ms <= self.t0_ms {
            return StrokeEval::default();
        }
        let u = ((t_ms - self.t0_ms) / self.duration_ms).clamp(0.0, 1.0);
        let (progress, ds_du) = normalized_sigma_lognormal(u, self.sigma);
        let lateral =
            self.arc.peak_offset * asymmetric_arc(progress, self.arc.alpha, self.arc.beta);
        StrokeEval {
            offset_x: self.nx.mul_add(lateral, self.dx * progress),
            offset_y: self.ny.mul_add(lateral, self.dy * progress),
            speed: self.dist * ds_du / self.duration_ms,
        }
    }
}

/// Builds a hardware polling timestamp schedule `(t_ms, delay_ms)` covering `[0, total_ms]`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn build_polling_schedule(
    total_ms: f64,
    config: MotionConfig,
    profile: &MotorProfile,
    rng: &mut SplitMix64,
) -> Vec<(f64, u64)> {
    let default_interval = MotionConfig::default().step_interval_ms;
    let base_interval = if config.step_interval_ms == default_interval {
        profile.polling_interval_ms.max(1)
    } else {
        config.step_interval_ms.max(1)
    } as f64;
    let jitter_sd = if profile.polling_jitter_ms.is_finite() {
        profile.polling_jitter_ms.clamp(0.0, base_interval * 0.4)
    } else {
        0.8
    };
    let min_dt = (base_interval * 0.5).max(1.0);
    let max_dt = (base_interval * 1.6).max(min_dt);

    let est = ((total_ms / base_interval).ceil() as usize)
        .saturating_add(4)
        .min(usize::try_from(MAX_STEPS).unwrap_or(10_000));
    let mut schedule = Vec::with_capacity(est);
    let max_steps_usize = usize::try_from(MAX_STEPS).unwrap_or(10_000);

    let mut t = 0.0;
    while t < total_ms && schedule.len() + 1 < max_steps_usize {
        let dt_raw = jitter_sd
            .mul_add(rng.next_normal(), base_interval)
            .clamp(min_dt, max_dt);
        let dt_ms = dt_raw.round().max(1.0) as u64;
        let next_t = t + dt_ms as f64;
        if next_t >= total_ms {
            let rem_ms = (total_ms - t).round().max(1.0) as u64;
            schedule.push((total_ms, rem_ms));
            t = total_ms;
            break;
        }
        t = next_t;
        schedule.push((t, dt_ms));
    }

    if schedule.is_empty() || (t - total_ms).abs() > 1e-6 {
        let rem_ms = (total_ms - t).round().max(1.0) as u64;
        schedule.push((total_ms, rem_ms));
    }
    if schedule.len() == 1 && total_ms >= 2.0 {
        let half = (total_ms * 0.5).round().max(1.0) as u64;
        let rest = (total_ms - half as f64).round().max(1.0) as u64;
        return vec![(total_ms * 0.5, half), (total_ms, rest)];
    }

    schedule
}

/// Generates a biomechanical pointer trajectory from `start` to `end` using `profile`.
///
/// Models directional Shannon Fitts's law duration scaling (using `target_bounds` when
/// known), an asymmetric Sigma-Lognormal primary velocity profile (peak velocity at
/// ~33%–40% of movement time), Meyer's overlapping corrective submovement on medium/high-ID
/// targets, asymmetric wrist-arc curvature, temporally correlated Ornstein-Uhlenbeck
/// signal-dependent noise, speed-damped 8–12 Hz physiological tremor, and a jittered
/// hardware polling clock. The final step always lands on exact `end`.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
pub fn plan_human_pointer_path_with_profile(
    start: Point,
    end: Point,
    target_bounds: Option<Bounds>,
    config: MotionConfig,
    profile: &MotorProfile,
    rng: &mut SplitMix64,
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

    let ux = dx / distance;
    let uy = dy / distance;
    let w_eff = target_bounds
        .filter(|b| b.width.is_finite() && b.height.is_finite() && b.width > 0.0 && b.height > 0.0)
        .map_or(24.0, |b| {
            let wx = b.width / ux.abs().max(1e-3);
            let wy = b.height / uy.abs().max(1e-3);
            wx.min(wy).clamp(8.0, 400.0)
        });
    let id = (1.0 + distance / w_eff).log2();

    let min_ms = (config.min_duration_ms.min(config.max_duration_ms) as f64).max(16.0);
    let max_ms = (config.min_duration_ms.max(config.max_duration_ms) as f64).max(min_ms);

    let fitts_a = if profile.fitts_a_ms.is_finite() {
        profile.fitts_a_ms.clamp(40.0, 300.0)
    } else {
        115.0
    };
    let fitts_b = if profile.fitts_b_ms.is_finite() {
        profile.fitts_b_ms.clamp(40.0, 300.0)
    } else {
        112.0
    };
    let dur_sigma = if profile.duration_sigma.is_finite() {
        profile.duration_sigma.clamp(0.01, 0.5)
    } else {
        0.14
    };
    let ln_sigma = if profile.lognormal_sigma.is_finite() {
        profile.lognormal_sigma.clamp(0.18, 0.45)
    } else {
        0.28
    };

    let median_mt = fitts_b.mul_add(id, fitts_a);
    let t1_ms = rng.next_lognormal_clamped(median_mt, dur_sigma, min_ms, max_ms);

    // Optional Meyer's overlapping corrective submovement on medium/high-ID moves.
    let overshoot_tendency = if profile.overshoot_tendency.is_finite() {
        profile.overshoot_tendency.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let correction_prob =
        (overshoot_tendency * ((id - 2.5) / 3.0).clamp(0.4, 1.4)).clamp(0.0, 0.70);
    let has_correction = distance >= 60.0 && id >= 3.0 && rng.next_f64() < correction_prob;

    let bias = if profile.arc_handedness_bias.is_finite() {
        profile.arc_handedness_bias.clamp(-0.45, 0.45)
    } else {
        0.0
    };
    let arc_sign = if rng.next_f64() < 0.5 + bias {
        1.0
    } else {
        -1.0
    };
    let base_arc = if config.arc_ratio.is_finite() && config.arc_ratio >= 0.0 {
        config.arc_ratio
    } else {
        0.0
    };
    let arc_scale = if profile.arc_ratio_scale.is_finite() {
        profile.arc_ratio_scale.clamp(0.3, 2.0)
    } else {
        1.0
    };
    let eff_arc_ratio = base_arc * arc_scale * rng.range_f64(0.45, 1.55);

    let (primary, secondary, total_ms) = if has_correction {
        let nx = -uy;
        let ny = ux;
        let along_err = if rng.next_f64() < 0.70 {
            (distance * rng.range_f64(0.025, 0.085)).clamp(4.0, 42.0)
        } else {
            -(distance * rng.range_f64(0.030, 0.070)).clamp(4.0, 35.0)
        };
        let lat_mag = rng.range_f64(2.0, 12.0).min(distance * 0.06);
        let lat_err = if rng.next_u64() & 1 == 0 {
            lat_mag
        } else {
            -lat_mag
        };
        let aim = Point {
            x: nx.mul_add(lat_err, ux.mul_add(along_err, end.x)),
            y: ny.mul_add(lat_err, uy.mul_add(along_err, end.y)),
        };

        let primary_dist = (aim.x - start.x).hypot(aim.y - start.y);
        let primary = StrokeSpec::between(
            start,
            aim,
            ArcParams {
                peak_offset: primary_dist * eff_arc_ratio * arc_sign,
                alpha: rng.range_f64(0.75, 1.25),
                beta: rng.range_f64(0.75, 1.25),
            },
            0.0,
            t1_ms,
            ln_sigma,
        );

        let onset_ms = t1_ms * rng.range_f64(0.68, 0.82);
        let raw_corr_ms = (t1_ms * rng.range_f64(0.30, 0.48)).max(75.0);
        let max_total = (max_ms * 1.35).max(t1_ms + 75.0);
        let corr_duration_ms = raw_corr_ms.min((max_total - onset_ms).max(75.0));

        let corr_dist = (end.x - aim.x).hypot(end.y - aim.y);
        let sec_sign = if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
        let secondary = StrokeSpec::between(
            aim,
            end,
            ArcParams {
                peak_offset: corr_dist * (eff_arc_ratio * 0.6) * sec_sign,
                alpha: rng.range_f64(0.85, 1.15),
                beta: rng.range_f64(0.85, 1.15),
            },
            onset_ms,
            corr_duration_ms,
            (ln_sigma * 0.85).clamp(0.18, 0.35),
        );

        (
            primary,
            Some(secondary),
            (onset_ms + corr_duration_ms).max(t1_ms),
        )
    } else {
        let primary = StrokeSpec::between(
            start,
            end,
            ArcParams {
                peak_offset: distance * eff_arc_ratio * arc_sign,
                alpha: rng.range_f64(0.75, 1.25),
                beta: rng.range_f64(0.75, 1.25),
            },
            0.0,
            t1_ms,
            ln_sigma,
        );
        (primary, None, t1_ms)
    };

    let schedule = build_polling_schedule(total_ms, config, profile, rng);
    let len = schedule.len();

    let ou_tau = if profile.ou_tau_ms.is_finite() {
        profile.ou_tau_ms.clamp(15.0, 200.0)
    } else {
        60.0
    };
    let sdn_scale = if profile.sdn_scale.is_finite() {
        profile.sdn_scale.clamp(0.0, 2.0)
    } else {
        0.55
    };
    let tremor_freq = if profile.tremor_freq_hz.is_finite() {
        profile.tremor_freq_hz.clamp(6.0, 14.0)
    } else {
        10.0
    };
    let tremor_amp = if profile.tremor_amp_px.is_finite() {
        profile.tremor_amp_px.clamp(0.0, 0.8)
    } else {
        0.20
    };

    let phase_x = rng.range_f64(0.0, TAU);
    let phase_y = rng.range_f64(0.0, TAU);
    let mut ou_x = 0.0;
    let mut ou_y = 0.0;

    let mut path = Vec::with_capacity(len);
    for (idx, (t_ms, delay_ms)) in schedule.into_iter().enumerate() {
        if idx + 1 == len {
            path.push(MotionStep {
                point: end,
                delay: Duration::from_millis(delay_ms),
            });
            break;
        }

        let primary_eval = primary.eval(t_ms);
        let secondary_eval = secondary
            .as_ref()
            .map_or_else(StrokeEval::default, |sec| sec.eval(t_ms));

        let bx = start.x + primary_eval.offset_x + secondary_eval.offset_x;
        let by = start.y + primary_eval.offset_y + secondary_eval.offset_y;
        let speed_px_per_ms = primary_eval.speed + secondary_eval.speed;

        let u_global = (t_ms / total_ms).clamp(0.0, 1.0);
        let env = (PI * u_global).sin();

        // Ornstein-Uhlenbeck correlated signal-dependent noise.
        let dt = (delay_ms as f64).max(1.0);
        let phi = (-dt / ou_tau).exp();
        let innov_std = phi.mul_add(-phi, 1.0).max(0.0).sqrt();
        let sigma_sdn = sdn_scale * 0.85_f64.mul_add(speed_px_per_ms, 0.25).min(3.0);
        ou_x = phi.mul_add(ou_x, sigma_sdn * innov_std * rng.next_normal());
        ou_y = phi.mul_add(ou_y, sigma_sdn * innov_std * rng.next_normal());

        // Speed-damped physiological micro-tremor (8–12 Hz).
        let tremor_attenuation = 1.0 / (1.0 + speed_px_per_ms / 0.8);
        let omega_t = TAU * tremor_freq * (t_ms / 1000.0);
        let tx = tremor_amp * tremor_attenuation * env * (omega_t + phase_x).sin();
        let ty = tremor_amp * tremor_attenuation * env * (omega_t + phase_y).sin();

        path.push(MotionStep {
            point: Point {
                x: env.mul_add(ou_x, bx) + tx,
                y: env.mul_add(ou_y, by) + ty,
            },
            delay: Duration::from_millis(delay_ms),
        });
    }

    path
}

/// Generates a stochastic biomechanical pointer trajectory using [`MotorProfile::default`].
#[must_use]
pub fn plan_human_pointer_path(
    start: Point,
    end: Point,
    config: MotionConfig,
    rng: &mut SplitMix64,
) -> Vec<MotionStep> {
    plan_human_pointer_path_with_profile(start, end, None, config, &MotorProfile::default(), rng)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hand {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QwertyKeyPos {
    hand: Hand,
    /// 0 = index, 1 = middle, 2 = ring, 3 = pinky, 4 = thumb (space).
    finger: u8,
    /// 0 = number row, 1 = top alpha, 2 = home row, 3 = bottom row, 4 = spacebar.
    row: u8,
    col: u8,
    shifted: bool,
}

const fn unshifted_key(ch: char) -> (char, bool) {
    match ch {
        'A'..='Z' => (ch.to_ascii_lowercase(), true),
        '~' => ('`', true),
        '!' => ('1', true),
        '@' => ('2', true),
        '#' => ('3', true),
        '$' => ('4', true),
        '%' => ('5', true),
        '^' => ('6', true),
        '&' => ('7', true),
        '*' => ('8', true),
        '(' => ('9', true),
        ')' => ('0', true),
        '_' => ('-', true),
        '+' => ('=', true),
        '{' => ('[', true),
        '}' => (']', true),
        '|' => ('\\', true),
        ':' => (';', true),
        '"' => ('\'', true),
        '<' => (',', true),
        '>' => ('.', true),
        '?' => ('/', true),
        other => (other, false),
    }
}

const fn qwerty_key_pos(ch: char) -> Option<QwertyKeyPos> {
    const fn pos(hand: Hand, finger: u8, row: u8, col: u8, shifted: bool) -> QwertyKeyPos {
        QwertyKeyPos {
            hand,
            finger,
            row,
            col,
            shifted,
        }
    }
    let (base, shifted) = unshifted_key(ch);

    let p = match base {
        // Row 0: number row
        '`' => pos(Hand::Left, 3, 0, 0, shifted),
        '1' => pos(Hand::Left, 3, 0, 1, shifted),
        '2' => pos(Hand::Left, 2, 0, 2, shifted),
        '3' => pos(Hand::Left, 1, 0, 3, shifted),
        '4' => pos(Hand::Left, 0, 0, 4, shifted),
        '5' => pos(Hand::Left, 0, 0, 5, shifted),
        '6' => pos(Hand::Right, 0, 0, 6, shifted),
        '7' => pos(Hand::Right, 0, 0, 7, shifted),
        '8' => pos(Hand::Right, 1, 0, 8, shifted),
        '9' => pos(Hand::Right, 2, 0, 9, shifted),
        '0' => pos(Hand::Right, 3, 0, 10, shifted),
        '-' => pos(Hand::Right, 3, 0, 11, shifted),
        '=' => pos(Hand::Right, 3, 0, 12, shifted),
        // Row 1: QWERTY
        'q' => pos(Hand::Left, 3, 1, 0, shifted),
        'w' => pos(Hand::Left, 2, 1, 1, shifted),
        'e' => pos(Hand::Left, 1, 1, 2, shifted),
        'r' => pos(Hand::Left, 0, 1, 3, shifted),
        't' => pos(Hand::Left, 0, 1, 4, shifted),
        'y' => pos(Hand::Right, 0, 1, 5, shifted),
        'u' => pos(Hand::Right, 0, 1, 6, shifted),
        'i' => pos(Hand::Right, 1, 1, 7, shifted),
        'o' => pos(Hand::Right, 2, 1, 8, shifted),
        'p' => pos(Hand::Right, 3, 1, 9, shifted),
        '[' => pos(Hand::Right, 3, 1, 10, shifted),
        ']' => pos(Hand::Right, 3, 1, 11, shifted),
        '\\' => pos(Hand::Right, 3, 1, 12, shifted),
        // Row 2: ASDFGHJKL
        'a' => pos(Hand::Left, 3, 2, 0, shifted),
        's' => pos(Hand::Left, 2, 2, 1, shifted),
        'd' => pos(Hand::Left, 1, 2, 2, shifted),
        'f' => pos(Hand::Left, 0, 2, 3, shifted),
        'g' => pos(Hand::Left, 0, 2, 4, shifted),
        'h' => pos(Hand::Right, 0, 2, 5, shifted),
        'j' => pos(Hand::Right, 0, 2, 6, shifted),
        'k' => pos(Hand::Right, 1, 2, 7, shifted),
        'l' => pos(Hand::Right, 2, 2, 8, shifted),
        ';' => pos(Hand::Right, 3, 2, 9, shifted),
        '\'' => pos(Hand::Right, 3, 2, 10, shifted),
        // Row 3: ZXCVBNM
        'z' => pos(Hand::Left, 3, 3, 0, shifted),
        'x' => pos(Hand::Left, 2, 3, 1, shifted),
        'c' => pos(Hand::Left, 1, 3, 2, shifted),
        'v' => pos(Hand::Left, 0, 3, 3, shifted),
        'b' => pos(Hand::Left, 0, 3, 4, shifted),
        'n' => pos(Hand::Right, 0, 3, 5, shifted),
        'm' => pos(Hand::Right, 0, 3, 6, shifted),
        ',' => pos(Hand::Right, 1, 3, 7, shifted),
        '.' => pos(Hand::Right, 2, 3, 8, shifted),
        '/' => pos(Hand::Right, 3, 3, 9, shifted),
        // Spacebar
        ' ' => pos(Hand::Right, 4, 4, 5, false),
        _ => return None,
    };
    Some(p)
}

/// Plans a biomechanical keystroke sequence for `text` using QWERTY bigram geometry,
/// right-skewed lognormal hold/IKI timings, shift & row-jump penalties, and
/// word/punctuation cognitive burst pauses.
///
/// The final character always has `delay_after == Duration::ZERO`.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn plan_typing_sequence(
    text: &str,
    profile: &MotorProfile,
    rng: &mut SplitMix64,
) -> Vec<KeystrokeStep> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return Vec::new();
    }

    let base_iki = if profile.typing_iki_median_ms.is_finite() {
        profile.typing_iki_median_ms.clamp(45.0, 260.0)
    } else {
        115.0
    };
    let base_hold = if profile.typing_hold_median_ms.is_finite() {
        profile.typing_hold_median_ms.clamp(40.0, 160.0)
    } else {
        88.0
    };
    let word_pause_med = if profile.typing_word_pause_median_ms.is_finite() {
        profile.typing_word_pause_median_ms.clamp(20.0, 260.0)
    } else {
        72.0
    };

    let mut steps = Vec::with_capacity(chars.len());
    for (idx, &ch) in chars.iter().enumerate() {
        let next_ch = chars.get(idx + 1).copied();
        let hold_med = if next_ch == Some(ch) {
            base_hold * 0.88
        } else {
            base_hold
        };
        let hold_ms = sample_ms(rng, hold_med, 0.24, 30.0, 210.0, 88.0);

        let delay_after = next_ch.map_or(Duration::ZERO, |next| {
            let (multiplier, mut extra_ms) = match (qwerty_key_pos(ch), qwerty_key_pos(next)) {
                (Some(a), Some(b)) => {
                    let mult = if ch == ' ' || next == ' ' {
                        0.95
                    } else if a.hand != b.hand {
                        0.78
                    } else if a.row == b.row && a.col == b.col {
                        1.05
                    } else if a.finger == b.finger {
                        1.35
                    } else {
                        0.95
                    };
                    let mut extra = 0.0;
                    if ch != ' ' && next != ' ' && a.row.abs_diff(b.row) >= 2 {
                        extra += rng.range_f64(15.0, 28.0);
                    }
                    if !a.shifted && b.shifted {
                        extra += rng.range_f64(30.0, 70.0);
                    }
                    (mult, extra)
                }
                _ => (1.15, 0.0),
            };

            if matches!(ch, ' ' | '.' | ',' | '!' | '?' | ';' | ':') {
                extra_ms += rng.next_lognormal_clamped(word_pause_med, 0.42, 15.0, 420.0);
            }

            let iki = rng.next_lognormal_clamped(base_iki * multiplier, 0.34, 22.0, 520.0);
            let total_ms = (iki + extra_ms).round().clamp(18.0, 900.0) as u64;
            Duration::from_millis(total_ms)
        });

        steps.push(KeystrokeStep {
            ch,
            hold_ms,
            delay_after,
        });
    }

    steps
}

/// Returns the biomechanical rollover probability for transitioning from `prev` to `curr`,
/// or `0.0` when rollover is not biomechanically eligible.
fn rollover_probability(prev: char, curr: char, rollover_ratio: f64) -> f64 {
    if rollover_ratio <= 0.0 || prev == curr {
        return 0.0;
    }
    let (Some(a), Some(b)) = (qwerty_key_pos(prev), qwerty_key_pos(curr)) else {
        return 0.0;
    };
    if a.shifted || b.shifted {
        return 0.0;
    }
    if a.row == b.row && a.col == b.col {
        return 0.0;
    }
    if a.hand != b.hand {
        rollover_ratio
    } else if a.finger != b.finger {
        rollover_ratio * 0.55
    } else {
        0.0
    }
}

/// Plans a biomechanical keystroke timeline with authentic keystroke rollover.
///
/// Following Dhakal et al. (CHI 2018), key `k+1` is pressed before key `k` is released
/// on eligible alternating-hand and different-finger transitions.
///
/// Guarantees:
/// - Every `Down` has a matching `Up` for the exact same character.
/// - `Down` events appear in the exact character order of `text`.
/// - Shifted, control, non-ASCII, repeated-key, and same-finger transitions never overlap.
/// - At most 2 keys are held simultaneously at any point in the timeline.
/// - The first event always has `delay == Duration::ZERO`.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn plan_rollover_typing_events(
    text: &str,
    profile: &MotorProfile,
    rng: &mut SplitMix64,
) -> Vec<KeyTimelineEvent> {
    let steps = plan_typing_sequence(text, profile, rng);
    if steps.is_empty() {
        return Vec::new();
    }

    let rollover_ratio = if profile.typing_rollover_ratio.is_finite() {
        profile.typing_rollover_ratio.clamp(0.0, 0.70)
    } else {
        0.30
    };

    let n = steps.len();
    let mut down_t = Vec::with_capacity(n);
    let mut up_t = Vec::with_capacity(n);

    down_t.push(0u64);
    up_t.push(steps[0].hold_ms.max(1));

    for i in 1..n {
        let prev_ch = steps[i - 1].ch;
        let curr_ch = steps[i].ch;
        let prev_down = down_t[i - 1];
        let prev_up = up_t[i - 1];
        let prev_hold = prev_up.saturating_sub(prev_down);
        let curr_hold = steps[i].hold_ms.max(1);
        let delay_ms = u64::try_from(steps[i - 1].delay_after.as_millis()).unwrap_or(u64::MAX);

        let prob = rollover_probability(prev_ch, curr_ch, rollover_ratio);
        let use_rollover = prob > 0.0 && rng.next_f64() < prob;

        let min_down = if i >= 2 {
            prev_down
                .saturating_add(22)
                .max(up_t[i - 2].saturating_add(5))
        } else {
            prev_down.saturating_add(22)
        };

        let (curr_down, curr_up) = if use_rollover && min_down < prev_up {
            let overlap_frac = rng.range_f64(0.15, 0.55);
            let overlap_ms = ((prev_hold as f64) * overlap_frac).round().max(1.0) as u64;
            let cand_down = prev_up
                .saturating_sub(overlap_ms)
                .max(min_down)
                .min(prev_up.saturating_sub(1));
            let cand_up = cand_down
                .saturating_add(curr_hold)
                .max(prev_up.saturating_add(9));
            (cand_down, cand_up)
        } else {
            let cand_down = prev_up.saturating_add(delay_ms).max(min_down);
            let cand_up = cand_down
                .saturating_add(curr_hold)
                .max(prev_up.saturating_add(9));
            (cand_down, cand_up)
        };

        down_t.push(curr_down);
        up_t.push(curr_up);
    }

    // (timestamp_ms, priority [0 = Up, 1 = Down], char_index, ch, action)
    let mut raw: Vec<(u64, u8, usize, char, KeyAction)> = Vec::with_capacity(n * 2);
    for (idx, step) in steps.iter().enumerate() {
        raw.push((down_t[idx], 1, idx, step.ch, KeyAction::Down));
        raw.push((up_t[idx], 0, idx, step.ch, KeyAction::Up));
    }
    raw.sort_by_key(|&(t_ms, prio, idx, _, _)| (t_ms, prio, idx));

    let mut timeline = Vec::with_capacity(raw.len());
    let mut prev_t = 0u64;
    for (pos, (t_ms, _, _, ch, action)) in raw.into_iter().enumerate() {
        let delay = if pos == 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(t_ms.saturating_sub(prev_t))
        };
        prev_t = t_ms;
        timeline.push(KeyTimelineEvent { ch, action, delay });
    }
    timeline
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn plan_trackpad_inertial_scroll(
    delta_x: f64,
    delta_y: f64,
    damping: f64,
    rng: &mut SplitMix64,
) -> Vec<ScrollStep> {
    let b = if damping.is_finite() {
        damping.clamp(1.5, 8.0)
    } else {
        3.8
    };
    let count = usize::try_from(rng.range_u64(8, 18)).unwrap_or(12);
    let mut weights = Vec::with_capacity(count);
    let mut weight_sum = 0.0;
    for i in 0..count {
        let w = match i {
            0 => 0.62,
            1 => 1.0,
            _ => (-b * ((i - 1) as f64 * 0.0167)).exp().max(0.05),
        };
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
        let frame_ms = 1.2_f64
            .mul_add(rng.next_normal(), 16.67)
            .round()
            .clamp(11.0, 23.0) as u64;
        steps.push(ScrollStep {
            delta_x: sx,
            delta_y: sy,
            delay: Duration::from_millis(frame_ms),
        });
    }
    steps
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn plan_wheel_detent_scroll(
    delta_x: f64,
    delta_y: f64,
    mag: f64,
    notch_px: f64,
    rng: &mut SplitMix64,
) -> Vec<ScrollStep> {
    let notch = if notch_px.is_finite() {
        notch_px.clamp(60.0, 180.0)
    } else {
        110.0
    };
    let raw_count = (mag / notch).round().clamp(3.0, 24.0) as u64;
    let count = usize::try_from(raw_count).unwrap_or(3);
    let mut weights = Vec::with_capacity(count);
    let mut weight_sum = 0.0;
    for _ in 0..count {
        let w = rng.range_f64(0.92, 1.08);
        weights.push(w);
        weight_sum += w;
    }

    let clutch_period = usize::try_from(rng.range_u64(4, 6)).unwrap_or(5);
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
        // Bell-shaped inter-notch delay: faster in the middle of a flick, slower at edges.
        let progress = if count > 1 {
            idx as f64 / (count - 1) as f64
        } else {
            0.5
        };
        let edge_factor = 2.0_f64.mul_add(progress, -1.0).abs();
        let notch_med = 24.0_f64.mul_add(edge_factor, 32.0);
        let mut delay_ms = sample_ms(rng, notch_med, 0.18, 24.0, 75.0, notch_med);
        if count >= 6 && idx > 0 && idx % clutch_period == 0 {
            delay_ms = delay_ms.saturating_add(sample_ms(rng, 175.0, 0.22, 130.0, 240.0, 175.0));
        }
        steps.push(ScrollStep {
            delta_x: sx,
            delta_y: sy,
            delay: Duration::from_millis(delay_ms),
        });
    }
    steps
}

/// Breaks a scroll delta into physically modeled inertial trackpad frames or ratcheted
/// wheel detents according to `profile.scroll_style`, preserving the exact `(delta_x, delta_y)` sum.
#[must_use]
pub fn plan_scroll_burst_with_profile(
    delta_x: f64,
    delta_y: f64,
    profile: &MotorProfile,
    rng: &mut SplitMix64,
) -> Vec<ScrollStep> {
    if !delta_x.is_finite() || !delta_y.is_finite() {
        return Vec::new();
    }
    let mag = delta_x.hypot(delta_y);
    if !mag.is_finite() || mag < 40.0 {
        return vec![ScrollStep {
            delta_x,
            delta_y,
            delay: Duration::ZERO,
        }];
    }

    match profile.scroll_style {
        ScrollStyle::TrackpadInertial { damping } => {
            plan_trackpad_inertial_scroll(delta_x, delta_y, damping, rng)
        }
        ScrollStyle::WheelDetent { notch_px } => {
            plan_wheel_detent_scroll(delta_x, delta_y, mag, notch_px, rng)
        }
    }
}

/// Breaks a scroll delta into smooth inertial scroll impulses whose total sum equals
/// `(delta_x, delta_y)`, using [`MotorProfile::default`].
#[must_use]
pub fn plan_scroll_burst(delta_x: f64, delta_y: f64, rng: &mut SplitMix64) -> Vec<ScrollStep> {
    plan_scroll_burst_with_profile(delta_x, delta_y, &MotorProfile::default(), rng)
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
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
        let max_slope = PI * MotionConfig::default().arc_ratio * 1.05;
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

    #[test]
    fn erfc_and_sigma_lognormal_math_primitives_are_accurate() {
        assert!((erfc_approx(0.0) - 1.0).abs() < 1e-7);
        assert!((erfc_approx(1.0) - 0.157_299_207).abs() < 1e-6);
        assert!((erfc_approx(-1.0) - 1.842_700_793).abs() < 1e-6);
        assert!((erfc_approx(3.0) - 0.000_022_090_5).abs() < 1e-6);
        assert!((erfc_approx(f64::INFINITY) - 0.0).abs() < f64::EPSILON);
        assert!((erfc_approx(f64::NEG_INFINITY) - 2.0).abs() < f64::EPSILON);

        assert!((sigma_lognormal_progress(0.0, 0.0, 0.3) - 0.0).abs() < f64::EPSILON);
        assert!((sigma_lognormal_progress(1.0, 0.0, 0.3) - 0.5).abs() < 1e-6);
        assert!(sigma_lognormal_progress(10.0, 0.0, 0.3) > 0.999);
    }

    #[test]
    fn sigma_lognormal_peak_velocity_is_asymmetric() {
        let mut rng = SplitMix64::new(1337);
        let profile = MotorProfile {
            overshoot_tendency: 0.0,
            ..MotorProfile::default()
        };
        let start = Point { x: 40.0, y: 120.0 };
        let end = Point { x: 640.0, y: 360.0 };

        let mut ratio_sum = 0.0;
        let trials = 50;
        for _ in 0..trials {
            let path = plan_human_pointer_path_with_profile(
                start,
                end,
                None,
                MotionConfig::default(),
                &profile,
                &mut rng,
            );
            assert_eq!(path.last().map(|s| s.point), Some(end));

            let total_ms: f64 = path.iter().map(|s| s.delay.as_secs_f64() * 1000.0).sum();
            let mut prev = start;
            let mut elapsed = 0.0;
            let mut peak_speed = -1.0;
            let mut peak_time = 0.0;
            for step in &path {
                let dt = (step.delay.as_secs_f64() * 1000.0).max(1.0);
                let dist = (step.point.x - prev.x).hypot(step.point.y - prev.y);
                let speed = dist / dt;
                let mid_t = 0.5_f64.mul_add(dt, elapsed);
                if speed > peak_speed {
                    peak_speed = speed;
                    peak_time = mid_t;
                }
                elapsed += dt;
                prev = step.point;
            }
            ratio_sum += peak_time / total_ms;
        }

        let mean_ratio = ratio_sum / f64::from(trials);
        assert!(
            (0.28..=0.46).contains(&mean_ratio),
            "expected left-skewed peak velocity ratio in [0.28, 0.46], got {mean_ratio:.4}"
        );
    }

    #[test]
    fn ou_lateral_noise_is_temporally_autocorrelated() {
        let mut rng = SplitMix64::new(2025);
        // Zero arc and zero overshoot so lateral coordinate `y` is purely OU noise + tremor.
        let profile = MotorProfile {
            overshoot_tendency: 0.0,
            tremor_amp_px: 0.0,
            sdn_scale: 0.8,
            ou_tau_ms: 65.0,
            polling_interval_ms: 8,
            ..MotorProfile::default()
        };
        let config = MotionConfig {
            arc_ratio: 0.0,
            min_duration_ms: 400,
            max_duration_ms: 650,
            ..MotionConfig::default()
        };
        let start = Point { x: 0.0, y: 0.0 };
        let end = Point { x: 800.0, y: 0.0 };

        let mut corr_sum = 0.0;
        let trials = 30;
        for _ in 0..trials {
            let path =
                plan_human_pointer_path_with_profile(start, end, None, config, &profile, &mut rng);
            // Exclude exact final endpoint.
            let ys: Vec<f64> = path[..path.len() - 1].iter().map(|s| s.point.y).collect();
            assert!(ys.len() >= 20);
            let mean = ys.iter().sum::<f64>() / ys.len() as f64;
            let mut num = 0.0;
            let mut den = 0.0;
            for i in 0..ys.len() - 1 {
                let a = ys[i] - mean;
                let b = ys[i + 1] - mean;
                num = a.mul_add(b, num);
                den = a.mul_add(a, den);
            }
            let r1 = if den > 1e-12 { num / den } else { 0.0 };
            corr_sum += r1;
        }

        let mean_corr = corr_sum / f64::from(trials);
        assert!(
            mean_corr > 0.3,
            "expected positive lag-1 autocorrelation > 0.3, got {mean_corr:.4}"
        );
    }

    #[test]
    fn high_id_moves_exhibit_corrective_overshoot_and_land_exact() {
        let mut rng = SplitMix64::new(9001);
        let profile = MotorProfile::default();
        let start = Point { x: 50.0, y: 200.0 };
        let end = Point { x: 750.0, y: 200.0 };
        let target_bounds = Bounds {
            x: 741.0,
            y: 191.0,
            width: 18.0,
            height: 18.0,
        };

        let mut overshoots = 0u32;
        let trials = 100;
        for _ in 0..trials {
            let path = plan_human_pointer_path_with_profile(
                start,
                end,
                Some(target_bounds),
                MotionConfig::default(),
                &profile,
                &mut rng,
            );
            assert_eq!(path.last().map(|s| s.point), Some(end));
            if path.iter().any(|s| s.point.x > end.x + 2.0) {
                overshoots += 1;
            }
        }

        assert!(
            overshoots >= 15,
            "expected at least 15% overshoots on high-ID moves, got {overshoots}/{trials}"
        );
    }

    #[test]
    fn entry_edge_bias_shifts_clicks_toward_approach_side() {
        let mut rng = SplitMix64::new(77);
        let profile = MotorProfile::default();
        let bounds = Bounds {
            x: 300.0,
            y: 200.0,
            width: 240.0,
            height: 40.0,
        };
        let approach_from_left = Point { x: 20.0, y: 220.0 };

        let mut sum_x = 0.0;
        let samples = 200;
        for _ in 0..samples {
            let p = pick_click_point_from(Some(approach_from_left), bounds, &profile, &mut rng);
            assert!(
                p.x >= 0.15_f64.mul_add(bounds.width, bounds.x) - 1e-9
                    && p.x <= 0.85_f64.mul_add(bounds.width, bounds.x) + 1e-9
            );
            assert!(
                p.y >= 0.15_f64.mul_add(bounds.height, bounds.y) - 1e-9
                    && p.y <= 0.85_f64.mul_add(bounds.height, bounds.y) + 1e-9
            );
            sum_x += p.x;
        }

        let mean_x = sum_x / f64::from(samples);
        let center_x = bounds.center().0;
        assert!(
            mean_x < center_x - 10.0,
            "expected entry-edge mean x ({mean_x:.2}) to sit left of center ({center_x:.2})"
        );
    }

    #[test]
    fn timing_distributions_are_right_skewed() {
        let mut rng = SplitMix64::new(31415);
        let profile = MotorProfile::default();
        let n = 500;

        let mut holds: Vec<f64> = (0..n)
            .map(|_| {
                let h = mouse_hold_for(&profile, &mut rng);
                assert!((35..=220).contains(&h));
                h as f64
            })
            .collect();
        let mut pauses: Vec<f64> = (0..n)
            .map(|_| {
                let p = hover_pause_for(&profile, &mut rng).as_millis();
                assert!((20..=260).contains(&p));
                p as f64
            })
            .collect();
        let mut ikis: Vec<f64> = (0..n)
            .map(|_| {
                let seq = plan_typing_sequence("ab", &profile, &mut rng);
                let ms = seq[0].delay_after.as_millis();
                assert!((18..=900).contains(&ms));
                ms as f64
            })
            .collect();

        for (label, vals) in [
            ("mouse_hold", &mut holds),
            ("hover_pause", &mut pauses),
            ("typing_iki", &mut ikis),
        ] {
            vals.sort_by(f64::total_cmp);
            let median = vals[n / 2];
            let mean = vals.iter().sum::<f64>() / n as f64;
            assert!(
                mean > median,
                "{label}: expected right-skewed mean ({mean:.2}) > median ({median:.2})"
            );
        }
    }

    #[test]
    fn qwerty_alternating_hand_bigrams_are_faster_than_same_finger() {
        let mut rng = SplitMix64::new(888);
        let profile = MotorProfile::default();
        let trials = 200;

        let mut alt_total = 0.0;
        let mut alt_count = 0usize;
        let mut same_total = 0.0;
        let mut same_count = 0usize;

        for _ in 0..trials {
            let alt = plan_typing_sequence("theandto", &profile, &mut rng);
            assert_eq!(alt.last().map(|s| s.delay_after), Some(Duration::ZERO));
            for step in &alt[..alt.len() - 1] {
                alt_total = step.delay_after.as_secs_f64().mul_add(1000.0, alt_total);
                alt_count += 1;
            }

            let same = plan_typing_sequence("dedswjulo", &profile, &mut rng);
            assert_eq!(same.last().map(|s| s.delay_after), Some(Duration::ZERO));
            for step in &same[..same.len() - 1] {
                same_total = step.delay_after.as_secs_f64().mul_add(1000.0, same_total);
                same_count += 1;
            }
        }

        let alt_mean = alt_total / alt_count as f64;
        let same_mean = same_total / same_count as f64;
        assert!(
            alt_mean < same_mean * 0.85,
            "expected alternating hands ({alt_mean:.2} ms) significantly faster than same-finger ({same_mean:.2} ms)"
        );
    }

    #[test]
    fn scroll_profiles_preserve_exact_totals() {
        let mut rng = SplitMix64::new(555);
        for style in [
            ScrollStyle::TrackpadInertial { damping: 3.6 },
            ScrollStyle::WheelDetent { notch_px: 105.0 },
        ] {
            let profile = MotorProfile {
                scroll_style: style,
                ..MotorProfile::default()
            };
            let steps = plan_scroll_burst_with_profile(120.0, -640.0, &profile, &mut rng);
            assert!(steps.len() >= 3, "style {style:?} produced too few steps");
            let sum_x: f64 = steps.iter().map(|s| s.delta_x).sum();
            let sum_y: f64 = steps.iter().map(|s| s.delta_y).sum();
            assert!((sum_x - 120.0).abs() < 1e-9, "sum_x mismatch for {style:?}");
            assert!((sum_y + 640.0).abs() < 1e-9, "sum_y mismatch for {style:?}");
        }
    }

    #[test]
    fn click_slip_stays_safely_within_bounds() {
        let mut rng = SplitMix64::new(123);
        let profile = MotorProfile {
            click_slip_prob: 1.0,
            ..MotorProfile::default()
        };
        let bounds = Bounds {
            x: 100.0,
            y: 100.0,
            width: 50.0,
            height: 20.0,
        };
        let origin = Point { x: 125.0, y: 110.0 };
        for _ in 0..100 {
            let slipped = plan_click_slip(origin, Some(bounds), &profile, &mut rng);
            assert!(slipped.is_some());
            if let Some(p) = slipped {
                assert!(p.x >= bounds.x + 2.0 && p.x <= bounds.x + bounds.width - 2.0);
                assert!(p.y >= bounds.y + 2.0 && p.y <= bounds.y + bounds.height - 2.0);
                let d = (p.x - origin.x).hypot(p.y - origin.y);
                assert!((0.49..=1.81).contains(&d));
            }
        }
    }

    #[test]
    fn rollover_timeline_preserves_order_matches_pairs_and_caps_at_two_held() {
        let mut rng = SplitMix64::new(4242);
        let profile = MotorProfile {
            typing_rollover_ratio: 0.45,
            ..MotorProfile::default()
        };
        let text = "thelandwithformand Hello, World!\t\n123 café";
        let events = plan_rollover_typing_events(text, &profile, &mut rng);

        assert_eq!(events.len(), text.chars().count() * 2);
        assert_eq!(events.first().map(|e| e.delay), Some(Duration::ZERO));

        let mut downs = String::new();
        let mut held: Vec<char> = Vec::new();
        let mut max_held = 0usize;
        for ev in &events {
            match ev.action {
                KeyAction::Down => {
                    downs.push(ev.ch);
                    held.push(ev.ch);
                    max_held = max_held.max(held.len());
                }
                KeyAction::Up => {
                    let pos = held.iter().position(|&c| c == ev.ch);
                    assert!(pos.is_some(), "Up without matching Down for {:?}", ev.ch);
                    if let Some(idx) = pos {
                        let _ = held.remove(idx);
                    }
                }
            }
        }
        assert_eq!(downs, text);
        assert_eq!(held, Vec::<char>::new(), "all keys must be released at end");
        assert!(
            max_held <= 2,
            "at most 2 keys may be held simultaneously, observed {max_held}"
        );
    }

    #[test]
    fn rollover_occurs_on_alternating_hand_text_with_at_least_15_percent_overlap() {
        let mut rng = SplitMix64::new(7777);
        let profile = MotorProfile::default();
        let text = "thelandwithformand";
        let trials = 40;
        let mut total_transitions = 0usize;
        let mut overlapping_transitions = 0usize;

        for _ in 0..trials {
            let events = plan_rollover_typing_events(text, &profile, &mut rng);
            let mut held_count = 0usize;
            let mut max_held = 0usize;
            let mut down_seen = 0usize;
            for ev in &events {
                match ev.action {
                    KeyAction::Down => {
                        if down_seen > 0 {
                            total_transitions += 1;
                            if held_count > 0 {
                                overlapping_transitions += 1;
                            }
                        }
                        down_seen += 1;
                        held_count += 1;
                        max_held = max_held.max(held_count);
                    }
                    KeyAction::Up => {
                        assert!(held_count > 0);
                        held_count -= 1;
                    }
                }
            }
            assert_eq!(held_count, 0);
            assert!(max_held <= 2);
        }

        let ratio = overlapping_transitions as f64 / total_transitions as f64;
        assert!(
            ratio >= 0.15,
            "expected >= 15% rollover overlap on alternating-hand text, got {:.1}% ({overlapping_transitions}/{total_transitions})",
            ratio * 100.0
        );
    }

    #[test]
    fn rollover_never_overlaps_same_finger_repeated_or_shifted_transitions() {
        let mut rng = SplitMix64::new(9999);
        let profile = MotorProfile {
            typing_rollover_ratio: 0.70,
            ..MotorProfile::default()
        };

        for text in [
            "dedced", "swxws", "jujmj", "ssss", "llll", "AbCd", "A!B@C#", "a\nb\tc",
        ] {
            for _ in 0..20 {
                let events = plan_rollover_typing_events(text, &profile, &mut rng);
                let mut held = 0usize;
                for ev in &events {
                    match ev.action {
                        KeyAction::Down => {
                            assert_eq!(
                                held, 0,
                                "unexpected rollover overlap in {text:?} on {:?}",
                                ev.ch
                            );
                            held += 1;
                        }
                        KeyAction::Up => {
                            assert_eq!(held, 1);
                            held -= 1;
                        }
                    }
                }
                assert_eq!(held, 0);
            }
        }
    }

    #[test]
    fn rollover_handles_empty_string_and_non_finite_ratio() {
        let mut rng = SplitMix64::new(1);
        let profile = MotorProfile {
            typing_rollover_ratio: f64::NAN,
            ..MotorProfile::default()
        };
        assert_eq!(
            plan_rollover_typing_events("", &profile, &mut rng),
            Vec::<KeyTimelineEvent>::new()
        );

        let events = plan_rollover_typing_events("the", &profile, &mut rng);
        assert_eq!(events.len(), 6);
    }
}
