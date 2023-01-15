// use std::collections::HashMap;
// use std::str::FromStr;
// use read_input::{InputBuild, InputConstraints};
// use read_input::prelude::input;


fn main() {
//     let choice: u8 = input()
//         .msg("\
// Welcome to the vault software !
// Please choose an option:
// 
// 1. Create a new organization
// 2. Log in
// ")
//         .inside([1, 2])
//         .get();
// 
//     if choice == 1 {
//         create_new_organization();
//     } else {
//         log_in();
//     }
}

// 
// fn create_new_organization() {
//     let organization_name: String = input()
//         .msg("Please enter your organization name: ")
//         .get();
// 
//     let nb_users: u8 = input()
//         .msg("How many users do you want to create for your organization ? ")
//         .min(2)
//         .get();
// 
//     let user_credentials: HashMap<String, String> = HashMap::new();
//     for _ in 0..nb_users{
//         let username : String = input()
//             .msg("Enter a username: ")
//             .add_test(|name: &String| !user_credentials.clone().contains_key(name))
//             .get();
//     }
// }
// 
// fn log_in() {}
