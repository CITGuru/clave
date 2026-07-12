//! Portable Clave Edge geometry — the OS-free half of the visual border overlay
//! ([doc 09](../../../docs/09-visual-border-overlay.md)): given the on-screen windows and which are
//! work windows, compute the rectangles to paint.
//!
//! The Edge is drawn as an inset ring — the outermost `thickness` pixels inside each work window's
//! rect — so occlusion is exact and free: an occluder over the window also covers that part of the
//! border.

use std::collections::HashMap;

use clave_platform::{Rgba, WindowId};

/// An axis-aligned pixel rectangle. Units are whatever the OS layer feeds in; the core only does
/// integer geometry and never interprets the unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RectPx {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl RectPx {
    /// Construct a rectangle from origin + size.
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        RectPx { x, y, w, h }
    }
    /// The exclusive right edge (`x + w`).
    pub const fn right(&self) -> i32 {
        self.x + self.w
    }
    /// The exclusive bottom edge (`y + h`).
    pub const fn bottom(&self) -> i32 {
        self.y + self.h
    }
    /// True if the rectangle encloses no pixels.
    pub const fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }
    /// The overlapping rectangle, or `None` if the two don't intersect.
    pub fn intersect(&self, o: &RectPx) -> Option<RectPx> {
        let x = self.x.max(o.x);
        let y = self.y.max(o.y);
        let r = self.right().min(o.right());
        let b = self.bottom().min(o.bottom());
        if r > x && b > y {
            Some(RectPx::new(x, y, r - x, b - y))
        } else {
            None
        }
    }
}

/// The geometry of one on-screen top-level window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowGeom {
    pub window: WindowId,
    pub rect: RectPx,
}

impl WindowGeom {
    pub const fn new(window: WindowId, rect: RectPx) -> Self {
        WindowGeom { window, rect }
    }
}

/// How the Clave Edge should look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorderCfg {
    /// Ring width, in the same units as [`RectPx`].
    pub thickness: i32,
    pub color: Rgba,
}

impl Default for BorderCfg {
    fn default() -> Self {
        BorderCfg {
            thickness: 3,
            color: Rgba::CLAVE_EDGE,
        }
    }
}

/// One work window's computed border: opaque `segments` to fill in `color`, already clipped to the
/// window's visible (un-occluded) region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub window: WindowId,
    pub color: Rgba,
    pub segments: Vec<RectPx>,
}

/// The parts of `a` not covered by `hole` — 0..=4 disjoint rectangles.
fn subtract(a: RectPx, hole: RectPx) -> Vec<RectPx> {
    let Some(ix) = a.intersect(&hole) else {
        return if a.is_empty() { vec![] } else { vec![a] };
    };
    let mut out = Vec::with_capacity(4);
    // Full-width strip above the intersection.
    if ix.y > a.y {
        out.push(RectPx::new(a.x, a.y, a.w, ix.y - a.y));
    }
    // Full-width strip below the intersection.
    if ix.bottom() < a.bottom() {
        out.push(RectPx::new(a.x, ix.bottom(), a.w, a.bottom() - ix.bottom()));
    }
    // Left strip, limited to the intersection's vertical band.
    if ix.x > a.x {
        out.push(RectPx::new(a.x, ix.y, ix.x - a.x, ix.h));
    }
    // Right strip, limited to the intersection's vertical band.
    if ix.right() < a.right() {
        out.push(RectPx::new(ix.right(), ix.y, a.right() - ix.right(), ix.h));
    }
    out
}

/// Subtract `hole` from every rect in a region.
fn region_subtract(region: Vec<RectPx>, hole: RectPx) -> Vec<RectPx> {
    region
        .into_iter()
        .flat_map(|r| subtract(r, hole))
        .collect()
}

/// The four inset edge bands of `rect` at the given `thickness`.
fn ring(rect: RectPx, thickness: i32) -> Vec<RectPx> {
    if rect.is_empty() || thickness <= 0 {
        return vec![];
    }
    let t = thickness.min(rect.w).min(rect.h);
    let mut out = Vec::with_capacity(4);
    // Top band (full width).
    out.push(RectPx::new(rect.x, rect.y, rect.w, t));
    // Bottom band (full width), only if it doesn't overlap the top band.
    if rect.h > t {
        out.push(RectPx::new(rect.x, rect.bottom() - t, rect.w, t));
    }
    // Side bands fill only the gap between the top and bottom bands.
    let mid_h = rect.h - 2 * t;
    if mid_h > 0 {
        let mid_y = rect.y + t;
        out.push(RectPx::new(rect.x, mid_y, t, mid_h));
        if rect.w > t {
            out.push(RectPx::new(rect.right() - t, mid_y, t, mid_h));
        }
    }
    out
}

/// Compute the Clave Edge frames to paint. `windows` is every relevant on-screen top-level window
/// ordered front-to-back; `work` are the supervised windows that get a border. Each work window's
/// inset ring is clipped to the region left after subtracting the windows in front of it.
pub fn recompute_frames(windows: &[WindowGeom], work: &[WindowId], cfg: &BorderCfg) -> Vec<Frame> {
    frames_impl(windows, work, cfg.thickness, |_| cfg.color)
}

/// Like [`recompute_frames`], but a per-window `colors` override wins over `cfg.color`.
pub fn recompute_frames_themed(
    windows: &[WindowGeom],
    work: &[WindowId],
    cfg: &BorderCfg,
    colors: &HashMap<WindowId, Rgba>,
) -> Vec<Frame> {
    frames_impl(windows, work, cfg.thickness, |w| {
        colors.get(&w).copied().unwrap_or(cfg.color)
    })
}

fn frames_impl(
    windows: &[WindowGeom],
    work: &[WindowId],
    thickness: i32,
    color_of: impl Fn(WindowId) -> Rgba,
) -> Vec<Frame> {
    let mut frames = Vec::new();
    for (i, wg) in windows.iter().enumerate() {
        if !work.contains(&wg.window) || wg.rect.is_empty() {
            continue;
        }
        // Occluders are the windows in front (earlier in the front-to-back list).
        let mut visible = vec![wg.rect];
        for occ in &windows[..i] {
            visible = region_subtract(visible, occ.rect);
            if visible.is_empty() {
                break;
            }
        }
        if visible.is_empty() {
            continue;
        }
        let mut segments = Vec::new();
        for band in ring(wg.rect, thickness) {
            for v in &visible {
                if let Some(seg) = band.intersect(v) {
                    segments.push(seg);
                }
            }
        }
        if !segments.is_empty() {
            frames.push(Frame {
                window: wg.window,
                color: color_of(wg.window),
                segments,
            });
        }
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(id: u64, x: i32, y: i32, width: i32, height: i32) -> WindowGeom {
        WindowGeom::new(WindowId(id), RectPx::new(x, y, width, height))
    }

    /// Total pixel area covered by a set of (assumed disjoint) rects.
    fn area(rects: &[RectPx]) -> i64 {
        rects.iter().map(|r| r.w as i64 * r.h as i64).sum()
    }

    #[test]
    fn ring_has_no_overlap_and_expected_area() {
        // 100x100 window, thickness 3: ring area = 100*100 - 94*94.
        let r = ring(RectPx::new(0, 0, 100, 100), 3);
        assert_eq!(area(&r), 100 * 100 - 94 * 94);
        // The four bands must be pairwise non-overlapping.
        for (a_i, a) in r.iter().enumerate() {
            for b in &r[a_i + 1..] {
                assert!(a.intersect(b).is_none(), "ring bands overlap: {a:?} {b:?}");
            }
        }
    }

    #[test]
    fn single_window_frames_all_four_edges() {
        let cfg = BorderCfg {
            thickness: 2,
            color: Rgba::CLAVE_EDGE,
        };
        let frames = recompute_frames(&[w(1, 10, 10, 200, 100)], &[WindowId(1)], &cfg);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].window, WindowId(1));
        // Whole ring visible → same area as an un-clipped ring.
        assert_eq!(area(&frames[0].segments), 200 * 100 - 196 * 96);
    }

    #[test]
    fn non_work_window_gets_no_frame() {
        let cfg = BorderCfg::default();
        let frames = recompute_frames(&[w(1, 0, 0, 50, 50)], &[WindowId(2)], &cfg);
        assert!(frames.is_empty());
    }

    #[test]
    fn fully_occluded_work_window_has_no_frame() {
        let cfg = BorderCfg::default();
        // Window 2 (front) completely covers window 1 (back, work).
        let windows = [w(2, -10, -10, 400, 400), w(1, 0, 0, 100, 100)];
        let frames = recompute_frames(&windows, &[WindowId(1)], &cfg);
        assert!(frames.is_empty());
    }

    #[test]
    fn partial_occlusion_removes_covered_border() {
        let cfg = BorderCfg {
            thickness: 4,
            color: Rgba::CLAVE_EDGE,
        };
        // Front window covers the top half of the work window (y 0..50 of a 0..100 window).
        let windows = [w(2, 0, 0, 100, 50), w(1, 0, 0, 100, 100)];
        let frames = recompute_frames(&windows, &[WindowId(1)], &cfg);
        assert_eq!(frames.len(), 1);
        // No painted segment may intersect the occluder.
        let occ = RectPx::new(0, 0, 100, 50);
        for seg in &frames[0].segments {
            assert!(
                seg.intersect(&occ).is_none(),
                "segment {seg:?} overlaps occluder"
            );
        }
        // The bottom band (y 96..100) survives in full.
        assert!(frames[0]
            .segments
            .iter()
            .any(|s| s.y == 96 && s.h == 4 && s.w == 100));
    }

    #[test]
    fn zero_thickness_produces_nothing() {
        let cfg = BorderCfg {
            thickness: 0,
            color: Rgba::CLAVE_EDGE,
        };
        let frames = recompute_frames(&[w(1, 0, 0, 100, 100)], &[WindowId(1)], &cfg);
        assert!(frames.is_empty());
    }

    #[test]
    fn subtract_of_disjoint_returns_original() {
        let a = RectPx::new(0, 0, 10, 10);
        let hole = RectPx::new(100, 100, 10, 10);
        assert_eq!(subtract(a, hole), vec![a]);
    }

    #[test]
    fn themed_frames_honor_per_window_color_override() {
        let cfg = BorderCfg {
            thickness: 2,
            color: Rgba::CLAVE_EDGE,
        };
        let red = Rgba {
            r: 0xFF,
            g: 0,
            b: 0,
            a: 0xFF,
        };
        let mut colors = HashMap::new();
        colors.insert(WindowId(1), red);

        let windows = [w(1, 0, 0, 50, 50), w(2, 100, 100, 50, 50)];
        let frames =
            recompute_frames_themed(&windows, &[WindowId(1), WindowId(2)], &cfg, &colors);
        assert_eq!(frames.len(), 2);
        // Window 1 has an override; window 2 falls back to the policy default.
        let c1 = frames.iter().find(|f| f.window == WindowId(1)).unwrap().color;
        let c2 = frames.iter().find(|f| f.window == WindowId(2)).unwrap().color;
        assert_eq!(c1, red);
        assert_eq!(c2, Rgba::CLAVE_EDGE);
    }

    #[test]
    fn recompute_frames_matches_themed_with_no_overrides() {
        let cfg = BorderCfg::default();
        let windows = [w(1, 0, 0, 80, 40)];
        let plain = recompute_frames(&windows, &[WindowId(1)], &cfg);
        let themed = recompute_frames_themed(&windows, &[WindowId(1)], &cfg, &HashMap::new());
        assert_eq!(plain, themed);
    }
}
