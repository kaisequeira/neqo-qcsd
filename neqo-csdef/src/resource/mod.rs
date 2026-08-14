// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

mod manifest;

pub use manifest::{
    ChaffManifest, ChaffQualification, ExpectedChaffResponse, IdentityChaffRequestHeaderPrimitive,
    QualifiedChaffResource, Resource, ResourceManifest, ResponseOnlyChaffManifest,
    ResponseOnlyChaffManifestV4, ResponseOnlyChaffQualification, ResponseOnlyChaffQualificationV4,
    ResponseOnlyQualifiedChaffResource, ResponseOnlyQualifiedChaffResourceV4,
    normalize_content_encoding, sanitize_chaff_headers,
};
