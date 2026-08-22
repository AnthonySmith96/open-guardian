# Releasing Open-Guardian

Runbook operacional. Cada paso existe porque algo falló sin él (v0.3.0: tag prematuro,
advisories RustSec a media release, coma perdida en el empaquetado Windows).

## Orden estricto

1. **Preparar la versión en una rama** (`vX.Y.Z-...`):
   - `Cargo.toml`: bump de `version`.
   - `CHANGELOG.md`: entrada `## vX.Y.Z - <título> (<fecha>)`.
   - Gate local completo antes de abrir el PR:
     ```bash
     cargo fmt -- --check
     cargo test --all-targets --locked
     cargo clippy --all-targets --all-features --locked -- -D warnings
     cargo check --all-targets --no-default-features --locked
     cargo build --release --locked
     git diff --check
     ```
2. **Abrir PR y esperar los 5 checks** de branch protection. Este repo **no tiene
   auto-merge** y `gh pr merge --admin` falla con checks pendientes: hay que esperar
   (ej. `gh pr checks --watch`) y fusionar normal.
3. **Fusionar el PR primero.** El tag se crea **después**, apuntando al **commit de merge**:
   ```bash
   git checkout main && git pull
   git tag "vX.Y.$Z"   # sobre el commit de merge que acaba de aterrizar
   git push origin "vX.Y.$Z"
   ```
   Si tageas antes del merge, el job `Verify release metadata` compara el tag contra la
   versión en `Cargo.toml` y falla en ~10 s sin artefactos. Recuperación: borrar tag
   local y remoto, fusionar, retaguear sobre el merge.
4. **El workflow `release.yml`** construye 4 plataformas (linux-amd64, macos-amd64,
   macos-arm64, windows-amd64), genera `SHA256SUMS` y attestations, y crea el release.
   Verificar en la pestaña Releases que quedó **Latest** con 5 assets.

## Empaquetado (cosas que ya rompieron un release)

- Unix usa `cp` con listas; Windows usa `Copy-Item` con **listas separadas por comas**.
  Una coma perdida = error de parámetro posicional en pwsh. Al editar `release.yml`,
  releer el bloque completo editado antes de commitear.
- El paquete incluye: binario, `guardian.toml`, `README.md`, `CHANGELOG.md`, `LICENSE`,
  `rules/*.toml`, `docs/adr/*.md`. Si se agregan directorios nuevos que deben viajar
  (p. ej. corpus), actualizar **ambos** steps de staging.

## Advisories RustSec en medio de un release

El CI audta con `cargo-audit` y falla el build ante advisories nuevos (una excepción
documentada: RUSTSEC-2026-0173, heredada de `age`).

```bash
git switch -c fix/advisory-<crate>
cargo update -p <crate>    # casi siempre existe versión parcheada
git add Cargo.lock && git commit -m "build: patch <crate> for <RUSTSEC-ID>"
```

PR → checks → merge. Solo como último recurso agregar una excepción al job de audit,
con justificación y fecha en el comentario y en el PR. Nunca commitear directamente en
main: branch protection rechaza el push y deja el historial sucio.
