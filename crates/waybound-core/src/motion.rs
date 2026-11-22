//! Biomechanical pointer motion planning using a minimum-jerk velocity profile
//! (Flash & Hogan) with Fitts's law duration scaling.

use std::time::Duration;

use crate::input::Point;

/// A single timed waypoint along a pointer trajectory.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MotionStep {
    /// Target pointer position at this step.
    pub point: Point,
    /// Delay to wait before emitting this step.
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
    /// Peak lateral arc offset as a fraction of total path distance (e.g., `0.04`).
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

/// Generates a smooth minimum-jerk pointer trajectory from `start` to `end`.
///
/// The `arc_sign` parameter (`+1.0` or `-1.0`) chooses which side of the chord
/// the gentle natural wrist arc bows toward.
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
    let dx = end.x - start.x;
    let dy = end.y - start.y;
    let distance = dx.hypot(dy);

    if distance < 1.0 {
        return vec![MotionStep {
            point: end,
            delay: Duration::ZERO,
        }];
    }

    // Fitts's law inspired duration: ~110ms + 75ms * log2(1 + distance / 20).
    let raw_ms = 75.0_f64.mul_add((1.0 + distance / 20.0).log2(), 110.0);
    let total_ms = raw_ms
        .round()
        .clamp(config.min_duration_ms as f64, config.max_duration_ms as f64)
        as u64;

    let interval = config.step_interval_ms.max(1);
    let steps = (total_ms / interval).max(2);

    // Unit normal perpendicular to the chord for subtle natural arc curvature.
    let nx = -dy / distance;
    let ny = dx / distance;
    let peak_offset = distance * config.arc_ratio * arc_sign.signum();

    let mut path = Vec::with_capacity(usize::try_from(steps).unwrap_or(64));
    for i in 1..=steps {
        let tau = i as f64 / steps as f64;
        let progress = minimum_jerk(tau);
        // Smooth bell curve sin(pi * tau) vanishes cleanly at start and end.
        let lateral = peak_offset * (std::f64::consts::PI * tau).sin();

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
}
