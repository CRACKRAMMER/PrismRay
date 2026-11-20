// SPDX-License-Identifier: MPL-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayVisualState {
    Idle,
    ProxyOnly,
    SystemProxy,
    TunOnly,
    TunAndSystemProxy,
}

impl TrayVisualState {
    pub fn from_flags(running: bool, tun_enabled: bool, system_proxy_enabled: bool) -> Self {
        if !running {
            return Self::Idle;
        }
        match (tun_enabled, system_proxy_enabled) {
            (true, true) => Self::TunAndSystemProxy,
            (true, false) => Self::TunOnly,
            (false, true) => Self::SystemProxy,
            (false, false) => Self::ProxyOnly,
        }
    }
}

fn blend_pixel(buf: &mut [u8], size: usize, x: i32, y: i32, color: [u8; 4]) {
    if x < 0 || y < 0 || x >= size as i32 || y >= size as i32 || color[3] == 0 {
        return;
    }
    let idx = (y as usize * size + x as usize) * 4;
    let src_a = color[3] as f32 / 255.0;
    let dst_a = buf[idx + 3] as f32 / 255.0;
    let out_a = src_a + dst_a * (1.0 - src_a);
    if out_a <= 0.0001 {
        return;
    }
    for c in 0..3 {
        let src = color[c] as f32;
        let dst = buf[idx + c] as f32;
        let blended = (src * src_a + dst * dst_a * (1.0 - src_a)) / out_a;
        buf[idx + c] = blended.clamp(0.0, 255.0) as u8;
    }
    buf[idx + 3] = (out_a * 255.0).clamp(0.0, 255.0) as u8;
}

fn lerp_rgb(a: [u8; 3], b: [u8; 3], t: f32) -> [u8; 3] {
    let t = t.clamp(0.0, 1.0);
    [
        (a[0] as f32 + (b[0] as f32 - a[0] as f32) * t) as u8,
        (a[1] as f32 + (b[1] as f32 - a[1] as f32) * t) as u8,
        (a[2] as f32 + (b[2] as f32 - a[2] as f32) * t) as u8,
    ]
}

fn dist_to_segment(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let abx = bx - ax;
    let aby = by - ay;
    let len_sq = abx * abx + aby * aby;
    if len_sq <= 1e-6 {
        return (px - ax).hypot(py - ay);
    }
    let t = (((px - ax) * abx + (py - ay) * aby) / len_sq).clamp(0.0, 1.0);
    let proj_x = ax + abx * t;
    let proj_y = ay + aby * t;
    (px - proj_x).hypot(py - proj_y)
}

fn draw_ray(
    buf: &mut [u8],
    size: usize,
    fx: f32,
    fy: f32,
    x: i32,
    y: i32,
    ax: f32,
    ay: f32,
    bx: f32,
    by: f32,
    half_width: f32,
    rgb: [u8; 3],
    max_alpha: f32,
) {
    let d = dist_to_segment(fx, fy, ax, ay, bx, by);
    // Thin dark contrast halo so bright rays remain legible on light desktop panels
    if d <= half_width + 1.8 {
        let halo_aa = ((half_width + 1.8 - d) / 1.2).clamp(0.0, 1.0);
        blend_pixel(buf, size, x, y, [15, 23, 42, (halo_aa * max_alpha * 0.55) as u8]);
    }
    if d <= half_width + 0.6 {
        let fill_aa = ((half_width + 0.6 - d) / 1.1).clamp(0.0, 1.0);
        blend_pixel(buf, size, x, y, [rgb[0], rgb[1], rgb[2], (fill_aa * max_alpha) as u8]);
    }
}

/// Renders a transparent-backdrop 64x64 RGBA 3D optical prism + rays tray emblem with 5-state coloring.
pub fn render_tray_icon(state: TrayVisualState) -> (Vec<u8>, u32, u32) {
    const SIZE: usize = 64;
    let mut buf = vec![0u8; SIZE * SIZE * 4];

    // Palette per connection/tunnel state
    let (top_rgb, bot_rgb, ray1_rgb, ray2_rgb, ray3_rgb): (
        [u8; 3],
        [u8; 3],
        [u8; 3],
        [u8; 3],
        [u8; 3],
    ) = match state {
        TrayVisualState::Idle => (
            [148, 163, 184],
            [100, 116, 139],
            [148, 163, 184],
            [148, 163, 184],
            [100, 116, 139],
        ),
        TrayVisualState::ProxyOnly => (
            [129, 140, 248],
            [14, 165, 233],
            [103, 232, 249],
            [129, 140, 248],
            [192, 132, 252],
        ),
        TrayVisualState::SystemProxy => (
            [52, 211, 153],
            [5, 150, 105],
            [110, 231, 183],
            [52, 211, 153],
            [20, 184, 166],
        ),
        TrayVisualState::TunOnly => (
            [56, 189, 248],
            [37, 99, 235],
            [103, 232, 249],
            [56, 189, 248],
            [129, 140, 248],
        ),
        TrayVisualState::TunAndSystemProxy => (
            [34, 211, 238],
            [16, 185, 129],
            [103, 232, 249],
            [94, 234, 212],
            [52, 211, 153],
        ),
    };

    // Full-bleed prism geometry on transparent background (apex at (30.5, 5.5), base at y=56.5)
    let cx = 30.5_f32;
    let prism_top_y = 5.5_f32;
    let prism_bot_y = 56.5_f32;
    let prism_half_w = 24.5_f32;
    let ray_alpha = if state == TrayVisualState::Idle { 175.0 } else { 248.0 };

    for y in 0..SIZE {
        for x in 0..SIZE {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let ix = x as i32;
            let iy = y as i32;

            // 1. Incident white/silver beam from left + 3 refracted spectrum rays to right
            let in_color = if state == TrayVisualState::Idle {
                [148, 163, 184]
            } else {
                [248, 250, 252]
            };
            draw_ray(&mut buf, SIZE, fx, fy, ix, iy, 2.5, 36.5, 22.0, 29.5, 2.0, in_color, ray_alpha);
            draw_ray(&mut buf, SIZE, fx, fy, ix, iy, 38.0, 27.5, 61.0, 18.0, 2.1, ray1_rgb, ray_alpha);
            draw_ray(&mut buf, SIZE, fx, fy, ix, iy, 40.5, 33.5, 61.5, 33.0, 2.0, ray2_rgb, ray_alpha);
            draw_ray(&mut buf, SIZE, fx, fy, ix, iy, 43.0, 39.5, 59.5, 47.0, 1.9, ray3_rgb, ray_alpha);

            // 2. Central 3D faceted equilateral prism
            if fy >= prism_top_y - 3.0 && fy <= prism_bot_y + 3.0 {
                let prog = ((fy - prism_top_y) / (prism_bot_y - prism_top_y)).clamp(0.0, 1.0);
                let allowed_hw = prog * prism_half_w;
                let dist_x = (fx - cx).abs();
                let top_dist = prism_top_y - fy;
                let bot_dist = fy - prism_bot_y;
                // Euclidean approximation for crisp equilateral triangle SDF
                let side_dist = (dist_x - allowed_hw) * 0.90;
                let tri_sdf = side_dist.max(top_dist).max(bot_dist);

                let in_hollow_void = state == TrayVisualState::Idle && tri_sdf < -5.2;

                // Subtle dark outline halo around outer edges (and inner rim on Idle) for light-panel contrast
                if tri_sdf <= 2.1 && !in_hollow_void {
                    let outline_a = ((2.1 - tri_sdf) / 1.2).clamp(0.0, 1.0) * 195.0;
                    blend_pixel(&mut buf, SIZE, ix, iy, [15, 23, 42, outline_a as u8]);
                }

                if tri_sdf <= 0.85 && !in_hollow_void {
                    let aa = (0.85 - tri_sdf).clamp(0.0, 1.0);
                    let mut rgb = lerp_rgb(top_rgb, bot_rgb, prog);
                    if fx < cx {
                        rgb = lerp_rgb(
                            rgb,
                            if state == TrayVisualState::Idle {
                                [226, 232, 240]
                            } else {
                                [248, 250, 252]
                            },
                            if state == TrayVisualState::Idle { 0.28 } else { 0.48 },
                        );
                    }
                    // Specular facet ridge down center
                    if (fx - cx).abs() < 1.35 && state != TrayVisualState::Idle {
                        rgb = lerp_rgb(rgb, [255, 255, 255], 0.55);
                    }
                    // Inner bevel highlight along Idle frame
                    if state == TrayVisualState::Idle && tri_sdf > -2.0 {
                        rgb = lerp_rgb(rgb, [226, 232, 240], 0.35);
                    }
                    let fill_alpha = if state == TrayVisualState::Idle {
                        (aa * 235.0) as u8
                    } else {
                        (aa * 255.0) as u8
                    };
                    blend_pixel(&mut buf, SIZE, ix, iy, [rgb[0], rgb[1], rgb[2], fill_alpha]);
                }
            }
        }
    }

    // 3. Compact high-contrast bottom-right status dot/ring at (53.5, 53.5) for TUN & System Proxy
    let corner_badge: Option<([u8; 3], [u8; 3])> = match state {
        TrayVisualState::SystemProxy => Some(([245, 158, 11], [254, 243, 199])),
        TrayVisualState::TunOnly => Some(([34, 211, 238], [224, 242, 254])),
        TrayVisualState::TunAndSystemProxy => Some(([16, 185, 129], [34, 211, 238])),
        TrayVisualState::Idle | TrayVisualState::ProxyOnly => None,
    };

    if let Some((core_rgb, ring_rgb)) = corner_badge {
        let bx = 53.5_f32;
        let by = 53.5_f32;
        for y in 40..SIZE {
            for x in 40..SIZE {
                let fx = x as f32 + 0.5;
                let fy = y as f32 + 0.5;
                let dist = (fx - bx).hypot(fy - by);
                if dist <= 9.2 {
                    let aa = (9.2 - dist).clamp(0.0, 1.0);
                    blend_pixel(&mut buf, SIZE, x as i32, y as i32, [11, 15, 26, (aa * 245.0) as u8]);
                }
                if dist <= 7.2 {
                    let aa = (7.2 - dist).clamp(0.0, 1.0);
                    let rgb = if dist > 4.6 { ring_rgb } else { core_rgb };
                    blend_pixel(&mut buf, SIZE, x as i32, y as i32, [rgb[0], rgb[1], rgb[2], (aa * 255.0) as u8]);
                }
            }
        }
    }

    (buf, SIZE as u32, SIZE as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_five_tray_icons_are_valid_transparent_and_distinct() {
        let states = [
            TrayVisualState::Idle,
            TrayVisualState::ProxyOnly,
            TrayVisualState::SystemProxy,
            TrayVisualState::TunOnly,
            TrayVisualState::TunAndSystemProxy,
        ];
        let mut rendered = Vec::with_capacity(states.len());
        let mut opaque_counts = Vec::with_capacity(states.len());
        for s in states {
            let (buf, w, h) = render_tray_icon(s);
            assert_eq!(w, 64);
            assert_eq!(h, 64);
            assert_eq!(buf.len(), 64 * 64 * 4);
            // Outer corners must stay 100% transparent (no squircle background)
            assert_eq!(buf[3], 0, "top-left corner must be transparent for {:?}", s);
            assert_eq!(buf[(63) * 4 + 3], 0, "top-right corner must be transparent for {:?}", s);
            let opaque = buf.chunks_exact(4).filter(|px| px[3] >= 200).count();
            assert!(opaque > 250, "emblem for {:?} has too few opaque pixels: {}", s, opaque);
            opaque_counts.push(opaque);
            rendered.push(buf);
        }
        // Hollow Idle must have visibly fewer opaque pixels than solid ProxyOnly
        assert!(opaque_counts[0] < opaque_counts[1], "idle should be hollow");
        for i in 0..rendered.len() {
            for j in (i + 1)..rendered.len() {
                assert_ne!(rendered[i], rendered[j], "icons {} and {} collided", i, j);
            }
        }
    }
}
