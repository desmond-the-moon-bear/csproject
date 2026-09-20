
# Installation requirements

This project was built and tested with (and requires) Rust 1.98. Follow the
instructions on [this](https://rust-lang.org/tools/install/) page for your
operating system.

# How to

Before running the server create the "data" directory in the same folder as the
project. The file tree should look something like this:

```
.
├── Cargo.lock
├── Cargo.toml
├── convenience
...
├── data
├── deps
...
├── README.md
├── Rocket.toml
├── src
...
```

The Rocket.toml file contains the command which generates the key and
certificate needed by the (fixed) server in order for HTTPS to work. Create
those on your own or copy the ones from the `convenience` directory.

Rust features were used to implement the flawed and the correct version. By
default the fixed version will be built. In order to build and run the version
with flaws run:

```sh
cargo run --no-default-features
```

To run the version without the flaws run:

```sh
cargo run --no-default-features
```

**IMPORTANT**: When testing the flawed version use HTTP in the link in the
browser like so:

```
http://127.0.0.1:8000/
```

When testing the fixed version use HTTPS in the link in the browser like so:

```
https://127.0.0.1:8000/
```

**IMPORTANT**: Since the certificate is not actually valid you should follow the
instructions on your browser to "proceed anyway".

The admin password can be set by setting the ```ADMIN_PASS``` environment
variable. This needs to be done only once as it replaces a placeholder user in
the database, however, since the implementation changes between the flawed and
the fixed version, the admin password needs to be set again (in order for it to
be hashed or unhashed). If you don't want to start from scratch use the
ready-made databases from the ```convenience``` directory. Copy the
corresponding one to the ```data``` directory and rename it to
```database.sqlite```. The ready-made databases contain a couple of users called
```user1```, ```user2``` and so on (with passwords the same as the username),
and some point transactions between them. The admin password is ```admin```,
however, this is not treated as a flaw as it can be changed using the
environment variable.

# Note

I have vendored the ```rocket``` crate dependency in order to change its
dependencies so that ```sqlite``` can be dynamically built and linked on the
local machine instead of requiring you to install the dynamic library yourself.

There will be a bunch of warnings, but there should not be errors.

