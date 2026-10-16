use bytes::{Buf, Bytes};
use tonic::{
    Status,
    codec::{Codec, DecodeBuf, Decoder},
};

#[derive(Default)]
pub(crate) struct PreservingCodec<T>(std::marker::PhantomData<fn() -> T>);
pub(crate) struct RawDecoder;

impl<T: prost::Message + Default + 'static> Codec for PreservingCodec<T> {
    type Encode = T;
    type Decode = Bytes;
    type Encoder = tonic_prost::ProstEncoder<Self::Encode>;
    type Decoder = RawDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        Self::Encoder::default()
    }
    fn decoder(&mut self) -> Self::Decoder {
        RawDecoder
    }
}

impl Decoder for RawDecoder {
    type Item = Bytes;
    type Error = Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
        // Tonic handles gRPC framing/status; prost decodes after retaining unknown fields verbatim.
        Ok(Some(source.copy_to_bytes(source.remaining())))
    }
}
