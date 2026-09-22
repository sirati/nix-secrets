use zeroize::Zeroizing;

pub(crate) const CONTRIBUTION_BYTES: usize = 32;

pub(crate) fn fresh_contribution() -> Result<Zeroizing<[u8; CONTRIBUTION_BYTES]>, getrandom::Error>
{
    let mut bytes = Zeroizing::new([0_u8; CONTRIBUTION_BYTES]);
    getrandom::fill(bytes.as_mut())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_execution_gets_a_fresh_exact_length_contribution() {
        let first = fresh_contribution().unwrap();
        let second = fresh_contribution().unwrap();
        assert_eq!(first.len(), CONTRIBUTION_BYTES);
        assert_eq!(second.len(), CONTRIBUTION_BYTES);
        assert_ne!(*first, *second);
    }
}
