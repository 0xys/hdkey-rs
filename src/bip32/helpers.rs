use crate::error::{Error, PathError, SeedError};

pub fn split_i(i: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut i_right = [0u8; 32];
    i_right.copy_from_slice(&i[32..]);

    let mut i_left = [0u8; 32];
    i_left.copy_from_slice(&i[0..32]);

    (i_left, i_right)
}

pub fn transform_u32_to_u8a(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4]
}

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