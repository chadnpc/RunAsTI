# docs

A simple Proof of Concept in Go to spawn a new shell as TrustedInstaller. Read more about how this PoC works on this [blog about TrustedInstaller](https://fourcore.io/blogs/no-more-access-denied-i-am-trustedinstaller). It is important to note that this should be executed as a user which has SeDebugPrivileges. Upon execution, it will automatically ask for UAC in case it is not executed as as an Administrator.

![demo](https://user-images.githubusercontent.com/26490648/219342533-79d0cf34-0bf2-4f63-b805-34fca5aff012.gif)

## API

- RunAsTrustedInstaller
  - Use the `RunAsTrustedInstaller` function to pass any executable to be run with TrustedInstaller privileges.
