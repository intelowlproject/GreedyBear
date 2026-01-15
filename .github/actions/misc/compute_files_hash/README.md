# Composite action compute files hash

This action computes a single SHA256 hash of one or more files.
Given a **space separated list of file paths**, a new file is created by concatenating all those files together. Then the SHA256 hash of the newly created file is computed and returned as the output.

Before being joined together, each file is tested to ensure that it **exists** and that it is **a regular file**.

This action is useful when saving/restoring a cache in which a unique key is required. As a matter of fact, the hash is used as a part of the hash key.

## Documentation

### Inputs

* `file_paths` - Mandatory - Space separated list of file paths for which a single SHA256 hash will be computed.

### Outputs

* `computed_hash` - A SHA256 hash of the file obtained by joining (concatenating) all input files together.
