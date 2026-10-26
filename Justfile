default:
    @just --list

install:
    pnpm install --frozen-lockfile

lint:
    pnpm biome check .

fix:
    pnpm biome check --write .

typecheck:
    pnpm tsc --noEmit

test:
    pnpm vitest run

build:
    pnpm tsc

check: lint typecheck test build

clean:
    rm -rf dist *.tsbuildinfo

fresh: clean install check
