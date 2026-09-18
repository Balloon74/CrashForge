#[derive(Clone, Copy, Debug)]
pub struct MinimizerLimits {
    pub max_runs: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MinimizationResult {
    pub bytes: Vec<u8>,
    pub runs: usize,
    pub complete: bool,
}

pub fn minimize<F>(
    input: &[u8],
    limits: MinimizerLimits,
    mut preserves_crash: F,
) -> MinimizationResult
where
    F: FnMut(&[u8]) -> bool,
{
    let mut runs = 0;
    let mut complete = true;
    let initial_units = if input.contains(&b'\n') {
        split_lines(input)
    } else {
        input.iter().map(|byte| vec![*byte]).collect()
    };

    let (line_units, line_complete) = ddmin(
        initial_units,
        &mut runs,
        limits.max_runs,
        &mut preserves_crash,
    );
    complete &= line_complete;

    if !line_complete {
        return MinimizationResult {
            bytes: flatten(&line_units),
            runs,
            complete: false,
        };
    }

    let byte_units = flatten(&line_units)
        .into_iter()
        .map(|byte| vec![byte])
        .collect();
    let (byte_units, byte_complete) =
        ddmin(byte_units, &mut runs, limits.max_runs, &mut preserves_crash);
    complete &= byte_complete;

    MinimizationResult {
        bytes: flatten(&byte_units),
        runs,
        complete,
    }
}

fn ddmin<F>(
    mut units: Vec<Vec<u8>>,
    runs: &mut usize,
    max_runs: usize,
    preserves_crash: &mut F,
) -> (Vec<Vec<u8>>, bool)
where
    F: FnMut(&[u8]) -> bool,
{
    if units.len() < 2 {
        return (units, true);
    }

    let mut partitions = 2;
    loop {
        if *runs >= max_runs {
            return (units, false);
        }

        let groups = split_groups(units.len(), partitions);
        let mut reduced = false;
        for group in groups {
            if *runs >= max_runs {
                return (units, false);
            }

            let candidate = without_group(&units, &group);
            *runs += 1;
            if preserves_crash(&flatten(&candidate)) {
                units = candidate;
                partitions = partitions.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
        }

        if reduced {
            if units.len() < 2 {
                return (units, true);
            }
        } else if partitions >= units.len() {
            return (units, true);
        } else {
            partitions = (partitions * 2).min(units.len());
        }
    }
}

fn split_lines(input: &[u8]) -> Vec<Vec<u8>> {
    if input.is_empty() {
        return Vec::new();
    }

    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in input.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(input[start..=index].to_vec());
            start = index + 1;
        }
    }
    if start < input.len() {
        lines.push(input[start..].to_vec());
    }
    lines
}

fn split_groups(length: usize, groups: usize) -> Vec<Vec<usize>> {
    (0..groups)
        .map(|group| {
            let start = group * length / groups;
            let end = (group + 1) * length / groups;
            (start..end).collect()
        })
        .filter(|group: &Vec<usize>| !group.is_empty())
        .collect()
}

fn without_group(units: &[Vec<u8>], group: &[usize]) -> Vec<Vec<u8>> {
    units
        .iter()
        .enumerate()
        .filter(|(index, _)| !group.contains(index))
        .map(|(_, unit)| unit.clone())
        .collect()
}

fn flatten(units: &[Vec<u8>]) -> Vec<u8> {
    units.iter().flatten().copied().collect()
}
