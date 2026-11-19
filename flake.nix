{
  description = "Auditline: zero-runtime-dependency AI agent proxy, hash-chained audit log, native bounded policy engine, and reproducible dev/CI/prod environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs:
        let
          nodejs = pkgs.nodejs_24;
          pythonWithPil = pkgs.python313.withPackages (ps: [ ps.pillow ]);
          linuxSandboxDeps = pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.bubblewrap
            pkgs.util-linux
          ];
          attachmentDeps = [
            pkgs.tesseract
            pkgs.poppler_utils
            pythonWithPil
          ] ++ linuxSandboxDeps;

          auditline = pkgs.stdenvNoCC.mkDerivation {
            pname = "auditline";
            version = "1.0.0";
            src = ./.;
            nativeBuildInputs = [ nodejs pkgs.typescript ];
            buildPhase = ''
              runHook preBuild
              tsc --target ES2022 --module NodeNext --moduleResolution NodeNext \
                --allowJs --noCheck --outDir dist --rootDir . \
                src/*.ts src/bend/*.mjs
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib/auditline $out/bin
              cp -r dist console package.json $out/lib/auditline/
              cat > $out/bin/auditline <<EOF
              #!${pkgs.runtimeShell}
              exec ${nodejs}/bin/node $out/lib/auditline/dist/src/cli.js "\$@"
              EOF
              chmod +x $out/bin/auditline
              ln -s $out/bin/auditline $out/bin/ai-audit
              runHook postInstall
            '';
            meta = {
              description = "Zero-runtime-dependency AI agent audit proxy and native bounded policy engine";
              license = pkgs.lib.licenses.mit;
              mainProgram = "auditline";
            };
          };
        in
        {
          inherit auditline;
          default = auditline;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          ociImage = pkgs.dockerTools.buildLayeredImage {
            name = "auditline";
            tag = "latest";
            contents = [
              auditline
              nodejs
              pkgs.bashInteractive
              pkgs.coreutils
              pkgs.cacert
            ] ++ attachmentDeps;
            config = {
              Cmd = [ "${auditline}/bin/auditline" "serve" "--host" "0.0.0.0" "--log" "/data/audit.jsonl" ];
              ExposedPorts = { "8787/tcp" = {}; };
              Env = [
                "NODE_ENV=production"
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
              Volumes = { "/data" = {}; };
            };
          };
        });

      devShells = forAllSystems (pkgs:
        let
          nodejs = pkgs.nodejs_24;
          pythonWithPil = pkgs.python313.withPackages (ps: [ ps.pillow ]);
          linuxSandboxDeps = pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.bubblewrap
            pkgs.util-linux
          ];
          commonTools = [
            nodejs
            pythonWithPil
            pkgs.tesseract
            pkgs.poppler_utils
            pkgs.openjdk11_headless
            pkgs.jq
            pkgs.ripgrep
            pkgs.curl
            pkgs.git
          ] ++ linuxSandboxDeps;
        in
        {
          default = pkgs.mkShell {
            name = "auditline-dev";
            packages = commonTools;
            shellHook = ''
              export AUDITLINE_NIX_SHELL=1
            '';
          };

          productline = pkgs.mkShell {
            name = "auditline-productline";
            packages = commonTools ++ [
              pkgs.python313Packages.pip
              pkgs.python313Packages.virtualenv
            ] ++ pkgs.lib.optionals (pkgs ? temporal-cli) [ pkgs.temporal-cli ];
            shellHook = ''
              export AUDITLINE_NIX_SHELL=1
            '';
          };
        });

      apps = forAllSystems (pkgs:
        let
          pkg = self.packages.${pkgs.system}.auditline;
        in
        {
          default = { type = "app"; program = "${pkg}/bin/auditline"; };
          auditline = { type = "app"; program = "${pkg}/bin/auditline"; };
          ai-audit = { type = "app"; program = "${pkg}/bin/ai-audit"; };
        });

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
