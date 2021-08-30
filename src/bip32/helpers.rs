use crate::error::{Error, PathError, SeedError};

pub struct Node {
    pub index: u32,
    pub hardened: bool
}

pub fn valiidate_path(path: &str, allow_hardened: bool) -> Result<Vec<Node>, Error> {
    if !path.starts_with("m/"){
        return Err(Error::InvalidPath(PathError::InvalidHead));
    }
    let mut vec = vec![];
    let path = path.split("/");
    let path_vec: Vec<&str> = path.collect();
    
    for p in path_vec {
        if p.eq("m"){
            continue;
        }

        let hardened = p.ends_with("'");

        if hardened && !allow_hardened {
            return Err(Error::InvalidPath(PathError::HardenedNotAllowed));
        }

        let num_str = match hardened {
            false => p,
            true => {
                &p[..p.len()-1]
            }
        };

        let parsed = num_str.parse::<u32>();
        let index = match parsed {
            Ok(x) => x,
            Err(_) => {
                return Err(Error::InvalidPath(PathError::Unparsable));
            }
        };

        let node = Node {
            hardened,
            index
        };

        vec.push(node);
    }

    Ok(vec)
}