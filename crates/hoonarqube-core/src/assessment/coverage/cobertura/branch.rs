use std::collections::BTreeSet;

use hoonarqube_ir::assessment::CoverageCounter;

use super::super::{MAX_MEASUREMENTS, parse_nonnegative_u64};

pub(super) fn counts(
    branch: Option<&str>,
    condition: Option<&str>,
    missing: Option<&str>,
) -> Result<Option<CoverageCounter>, &'static str> {
    match branch {
        None | Some("false") if condition.is_none() && missing.is_none() => return Ok(None),
        Some("true") => {}
        _ => return Err("contradictory Cobertura branch attributes"),
    }
    let (percentage, ratio) = condition
        .and_then(|value| value.split_once('%'))
        .ok_or("branch line requires condition-coverage as 'P% (covered/total)'")?;
    let ratio = ratio
        .trim()
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'));
    let (covered, eligible) = ratio
        .and_then(|value| value.split_once('/'))
        .and_then(|(covered, eligible)| Some((integer(covered)?, integer(eligible)?)))
        .filter(|(covered, eligible)| {
            *eligible > 1 && *eligible <= MAX_MEASUREMENTS as u64 && covered <= eligible
        })
        .ok_or("invalid Cobertura branch counts")?;
    if integer(percentage) != Some(100 * covered / eligible) {
        return Err("Cobertura branch percentage contradicts its counts");
    }
    if let Some(missing) = missing {
        check_missing(missing, eligible - covered)?;
    }
    Ok(Some(CoverageCounter { eligible, covered }))
}

fn integer(text: &str) -> Option<u64> {
    parse_nonnegative_u64(text)
}

fn check_missing(missing: &str, expected: u64) -> Result<(), &'static str> {
    let mut destinations = BTreeSet::new();
    let mut count = 0;
    for destination in missing.split(',') {
        count += 1;
        if count > expected {
            return Err("Cobertura missing-branches contradicts its counts");
        }
        // coverage.py displays every negative destination as "exit".
        if destination.trim() != "exit"
            && !integer(destination).is_some_and(|number| {
                number > 0 && u32::try_from(number).is_ok() && destinations.insert(number)
            })
        {
            return Err("invalid Cobertura missing-branches destination");
        }
    }
    if count != expected {
        return Err("Cobertura missing-branches contradicts its counts");
    }
    Ok(())
}
