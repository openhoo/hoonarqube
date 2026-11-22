//! Exact insert/delete alignment for large files with a small edit distance.
//!
//! A path with at most k insertions/deletions stays within k diagonals of
//! the origin. Once a path of cost <= k reaches the last cell, *every*
//! optimal alignment is inside the band, including ties between repeated lines.

use super::{LineAlignment, MAX_ALIGNMENT_CELLS, reserve_alignment_work};

const UNREACHABLE: u32 = u32::MAX / 4;

struct Band {
    rows: usize,
    last_column: usize,
    radius: usize,
    stride: usize,
    costs: Vec<u32>,
}

impl Band {
    fn new(rows: usize, last_column: usize, radius: usize, stride: usize, cells: usize) -> Self {
        Self {
            rows,
            last_column,
            radius,
            stride,
            costs: vec![UNREACHABLE; cells],
        }
    }

    fn columns(&self, row: usize) -> std::ops::RangeInclusive<usize> {
        row.saturating_sub(self.radius)..=self.last_column.min(row.saturating_add(self.radius))
    }

    fn offset(&self, row: usize, column: usize) -> usize {
        row * self.stride + (column - row.saturating_sub(self.radius))
    }

    fn get(&self, row: usize, column: usize) -> u32 {
        if row >= self.rows || column > self.last_column || row.abs_diff(column) > self.radius {
            return UNREACHABLE;
        }
        self.costs[self.offset(row, column)]
    }

    fn set(&mut self, row: usize, column: usize, value: u32) {
        let index = self.offset(row, column);
        self.costs[index] = value;
    }

    fn fill_prefix(&mut self, current: &[String], reference: &[String]) {
        for i in 0..self.rows {
            for j in self.columns(i) {
                let cost = if i == 0 && j == 0 {
                    0
                } else {
                    let mut best = UNREACHABLE;
                    if i > 0 {
                        best = best.min(self.get(i - 1, j) + 1);
                    }
                    if j > 0 {
                        best = best.min(self.get(i, j - 1) + 1);
                    }
                    if i > 0 && j > 0 && current[i - 1] == reference[j - 1] {
                        best = best.min(self.get(i - 1, j - 1));
                    }
                    best
                };
                self.set(i, j, cost);
            }
        }
    }

    fn suffix(&self, current: &[String], reference: &[String]) -> Self {
        let mut tail = Self::new(
            self.rows,
            self.last_column,
            self.radius,
            self.stride,
            self.costs.len(),
        );
        for i in (0..self.rows).rev() {
            for j in self.columns(i).rev() {
                let cost = if i == current.len() && j == reference.len() {
                    0
                } else {
                    let mut best = (tail.get(i + 1, j) + 1).min(tail.get(i, j + 1) + 1);
                    if i < current.len() && j < reference.len() && current[i] == reference[j] {
                        best = best.min(tail.get(i + 1, j + 1));
                    }
                    best
                };
                tail.set(i, j, cost);
            }
        }
        tail
    }
}

fn exact_prefix(
    current: &[String],
    reference: &[String],
    work: &mut usize,
    limit: usize,
) -> Result<(Band, u32), String> {
    let error = || "baseline alignment matrix exceeds the bounded limit".to_string();
    let rows = current.len().checked_add(1).ok_or_else(error)?;
    let columns = reference.len().checked_add(1).ok_or_else(error)?;
    let mut radius = current.len().abs_diff(reference.len()).max(1);
    loop {
        let stride = radius.saturating_mul(2).saturating_add(1).min(columns);
        let cells = rows
            .checked_mul(stride)
            .filter(|&c| c <= MAX_ALIGNMENT_CELLS)
            .ok_or_else(error)?;
        reserve_alignment_work(work, limit, cells, 1)?;
        let mut band = Band::new(rows, reference.len(), radius, stride, cells);
        band.fill_prefix(current, reference);
        let distance = band.get(current.len(), reference.len());
        if usize::try_from(distance).is_ok_and(|d| d <= radius) {
            return Ok((band, distance));
        }
        radius = radius.checked_mul(2).ok_or_else(error)?;
    }
}

pub(super) fn lcs_length(
    current: &[String],
    reference: &[String],
    work: &mut usize,
    limit: usize,
) -> Result<usize, String> {
    let (_, distance) = exact_prefix(current, reference, work, limit)?;
    Ok((current.len() + reference.len() - distance as usize) / 2)
}

pub(super) fn align_lines(
    current: &[String],
    reference: &[String],
    work: &mut usize,
    limit: usize,
) -> Result<LineAlignment, String> {
    let (head, distance) = exact_prefix(current, reference, work, limit)?;
    reserve_alignment_work(work, limit, head.costs.len(), 2)?;
    let tail = head.suffix(current, reference);
    let mut new_line_indices = Vec::new();
    let mut uncertain = false;
    let mut membership_uncertain = false;
    for (i, line) in current.iter().enumerate() {
        let mut matches = 0;
        let mut can_skip = false;
        for j in head.columns(i) {
            let before = head.get(i, j);
            if before + 1 + tail.get(i + 1, j) == distance {
                can_skip = true;
            }
            if reference.get(j) == Some(line) && before + tail.get(i + 1, j + 1) == distance {
                matches += 1;
            }
        }
        if matches == 0 || can_skip {
            new_line_indices.push(i);
        }
        membership_uncertain |= matches != 0 && can_skip;
        uncertain |= matches > 1 || (matches != 0 && can_skip);
    }
    Ok(LineAlignment {
        new_line_indices,
        uncertain,
        membership_uncertain,
    })
}
