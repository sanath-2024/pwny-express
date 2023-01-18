// @generated automatically by Diesel CLI.

diesel::table! {
    passwords (id) {
        id -> Nullable<Integer>,
        name -> Text,
        value_hash -> Binary,
    }
}
