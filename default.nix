{ isShell ? false }:
let
  # Read in the Niv sources
  sources = import ./nix/sources.nix {};

  # Fetch the haskell.nix commit we have pinned with Niv
  haskellNix = import sources.haskellNix {};

  # haskell.nix provides access to the nixpkgs pins which are used by our CI,
  # hence you will be more likely to get cache hits when using these.
  # But you can also just use your own, e.g. '<nixpkgs>'.
  nixpkgs = haskellNix.sources.nixpkgs-2105;

  # Import nixpkgs and pass the haskell.nix provided nixpkgsArgs
  pkgs = import
    nixpkgs
    # These arguments passed to nixpkgs, include some patches and also
    # the haskell.nix functionality itself as an overlay.
    haskellNix.nixpkgsArgs;

  build = pkgs.haskell-nix.project {
    # 'cleanGit' cleans a source directory based on the files known by git
    src = pkgs.haskell-nix.haskellLib.cleanGit {
      name = "fido2";
      src = ./.;
    };
    # Specify the GHC version to use.
    compiler-nix-name = "ghc8107";
  };

  deploy = pkgs.writeShellScriptBin "deploy" ''
    ${pkgs.nixos-rebuild}/bin/nixos-rebuild switch --build-host localhost --target-host webauthn.dev.tweag.io \
      --use-remote-sudo --no-build-nix \
      -I nixpkgs=${toString nixpkgs} \
      -I nixos-config=${toString infra/configuration.nix}
  '';

  shell = build.shellFor {
    tools = {
      cabal = "3.4.0.0";
      hlint = "latest";
      haskell-language-server = "latest";
      ormolu = "latest";
    };

    nativeBuildInputs = with pkgs; [
      entr
      fd
      niv
      python310
      yarn
      nodejs
      deploy
      jq
    ];
  };

in
if isShell then shell else build
