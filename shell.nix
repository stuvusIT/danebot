with import <nixpkgs> {};

mkShell {
  name = "tlsabot-shell";

  buildInputs = [
    (python3.withPackages (p: with p; [
      black
      cryptography
      dns
      pylint
    ]))
  ];
}
