use trust_dns_client::rr::Name;

pub struct ZoneIterator {
    target: Name,
    current_level: u8,
}

impl Iterator for ZoneIterator {
    type Item = (Name, Name);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_level >= self.target.num_labels() {
            return None;
        }

        self.current_level += 1;

        Some((
            self.target.trim_to((self.current_level - 1).into()),
            self.target.trim_to((self.current_level).into()),
        ))
    }
}

pub fn iter(name: Name, origin: Name) -> ZoneIterator {
    ZoneIterator {
        target: name,
        current_level: origin.num_labels(),
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_iter_root() {
        let iter = iter(Name::root(), Name::root());
    }
}
