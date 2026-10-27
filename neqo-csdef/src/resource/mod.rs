// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

mod manifest;
mod ft_supplemental;
pub use ft_supplemental::{FtSupplementalChaffManifestV7, FtSupplementalPoolSource,
    FtSupplementalQualification, FtSupplementalQualifiedResource, FtPoolPreparedResponse,
    FT_POOL_ID_MIN, FT_POOL_ID_MAX, FT_SUPPLEMENTAL_POLICY};

pub use manifest::{
    ChaffManifest, ChaffQualification, ExpectedChaffResponse, IdentityChaffRequestHeaderPrimitive,
    QualifiedChaffResource, Resource, ResourceManifest, ResponseOnlyChaffManifest,
    ResponseOnlyChaffManifestV4, ResponseOnlyChaffManifestV6, ResponseOnlyChaffQualification,
    ResponseOnlyChaffQualificationV4, ResponseOnlyChaffQualificationV6,
    ResponseOnlyQualifiedChaffResource, ResponseOnlyQualifiedChaffResourceV4,
    ResponseOnlyQualifiedChaffResourceV6, SmallResponseAggregateCapacityContract,
    normalize_content_encoding, sanitize_chaff_headers,
};
