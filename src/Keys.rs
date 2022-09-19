use std::io;
use ff::{PrimeField, PrimeFieldBits};
use group::Curve;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "pairing")]
use bls12_381::{hash_to_curve::HashToField, G1Affine, G1Projective, Scalar};
#[cfg(feature = "pairing")]
use hkdf::Hkdf;
#[cfg(feature = "pairing")]
use sha2::{digest::generic_array::typenum::U48, digest::generic_array::GenericArray, Sha256};

#[cfg(feature = "blst")]
use blstrs::{G1Affine, G1Projective, G2Affine, Scalar};
#[cfg(feature = "blst")]
use group::prime::PrimeCurveAffine;

pub(crate) struct ScalarRepr(<Scalar as PrimeFieldBits>::ReprBits);

use Error;
crate::Signatures::Signature!

pub(crate) const G1_COMPRESSED_SIZE: usize = 48;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PublicKey(pub G1Projective);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PrivateKey(pub Scalar);

impl From<G1Projective> for PublicKey {
    fn from(val: G1Projective) -> Self {
        PublicKey(val)
    }
}

impl From<PublicKey> for G1Projective {
    fn from(val: PublicKey) -> Self {
        val.0
    }
}

impl From<Scalar> for PrivateKey {
    fn from(val: Scalar) -> Self {
        PrivateKey(val)
    }
}

impl From<PrivateKey> for Scalar {
    fn from(val: PrivateKey) -> Self {
        val.0
    }
}

impl From<PrivateKey> for ScalarRepr {
    fn from(val: PrivateKey) -> Self {
        ScalarRepr(val.0.to_le_bits().into_inner())
    }
}

impl<'a> From<&'a PrivateKey> for ScalarRepr {
    fn from(val: &'a PrivateKey) -> Self {
        (*val).into()
    }
}

pub trait Serialize: ::std::fmt::Debug + Sized {

    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()>;

    fn from_bytes(raw: &[u8]) -> Result<Self, Error>;

    fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(8 * 4);
        self.write_bytes(&mut res).expect("preallocated");
        res
    }
}

impl PrivateKey {

    pub fn new<T: AsRef<[u8]>>(msg: T) -> Self {
        PrivateKey(key_gen(msg))
    }

    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {

        let mut ikm = [0u8; 32];
        rng.try_fill_bytes(&mut ikm)
            .expect("unable to produce secure randomness");

        Self::new(ikm)
    }

    #[cfg(feature = "pairing")]
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        let mut p = hash(message.as_ref());
        p *= self.0;

        p.into()
    }

    #[cfg(feature = "blst")]
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        let p = hash(message.as_ref());
        let mut sig = G2Affine::identity();

        unsafe {
            blst_lib::blst_sign_pk2_in_g1(
                std::ptr::null_mut(),
                sig.as_mut(),
                p.as_ref(),
                &self.0.into(),
            );
        }

        sig.into()
    }

    #[cfg(feature = "pairing")]
    pub fn public_key(&self) -> PublicKey {
        let mut pk = G1Projective::generator();
        pk *= self.0;

        PublicKey(pk)
    }

    #[cfg(feature = "blst")]
    pub fn public_key(&self) -> PublicKey {
        let mut pk = G1Affine::identity();

        unsafe {
            blst_lib::blst_sk_to_pk2_in_g1(std::ptr::null_mut(), pk.as_mut(), &self.0.into());
        }

        PublicKey(pk.into())
    }

    pub fn from_string<T: AsRef<str>>(s: T) -> Result<Self, Error> {
        match Scalar::from_str_vartime(s.as_ref()) {
            Some(f) => Ok(f.into()),
            None => Err(Error::InvalidPrivateKey),
        }
    }
}

impl Serialize for PrivateKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        for digit in &self.0.to_le_bits().data {
            dest.write_all(&digit.to_le_bytes())?;
        }

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        const FR_SIZE: usize = (Scalar::NUM_BITS as usize + 8 - 1) / 8;
        if raw.len() != FR_SIZE {
            return Err(Error::SizeMismatch);
        }

        let mut res = [0u8; FR_SIZE];
        res.copy_from_slice(&raw[..FR_SIZE]);


        Scalar::from_repr_vartime(res)
            .map(Into::into)
            .ok_or(Error::InvalidPrivateKey)
    }
}

impl PublicKey {
    pub fn as_affine(&self) -> G1Affine {
        self.0.to_affine()
    }

    pub fn verify<T: AsRef<[u8]>>(&self, sig: Signature, message: T) -> bool {
        verify_messages(&sig, &[message.as_ref()], &[*self])
    }
}

impl Serialize for PublicKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        let t = self.0.to_affine();
        let tmp = t.to_compressed();
        dest.write_all(tmp.as_ref())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != G1_COMPRESSED_SIZE {
            return Err(Error::SizeMismatch);
        }

        let mut res = [0u8; G1_COMPRESSED_SIZE];
        res.as_mut().copy_from_slice(raw);
        let affine: G1Affine =
            Option::from(G1Affine::from_compressed(&res)).ok_or(Error::GroupDecode)?;

        Ok(PublicKey(affine.into()))
    }
}

#[cfg(feature = "pairing")]
fn key_gen<T: AsRef<[u8]>>(data: T) -> Scalar {
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

    let data = data.as_ref();
    assert!(data.len() >= 32, "IKM must be at least 32 bytes");

    let mut msg = data.as_ref().to_vec();

    msg.push(0);
    let prk = Hkdf::<Sha256>::new(Some(SALT), &msg);

    let mut result = GenericArray::<u8, U48>::default();
    assert!(prk.expand(&[0, 48], &mut result).is_ok());

    Scalar::from_okm(&result)
}

#[cfg(feature = "blst")]
fn key_gen<T: AsRef<[u8]>>(data: T) -> Scalar {
    use std::convert::TryInto;

    let data = data.as_ref();
    assert!(data.len() >= 32, "IKM must be at least 32 bytes");

    let key_info = &[];
    let mut out = blst_lib::blst_scalar::default();
    unsafe {
        blst_lib::blst_keygen(
            &mut out,
            data.as_ptr(),
            data.len(),
            key_info.as_ptr(),
            key_info.len(),
        )
    };

    out.try_into().expect("invalid key generated")
}