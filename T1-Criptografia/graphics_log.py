#!/usr/bin/env python3

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


SCENARIOS = ["scenario-01", "scenario-02", "scenario-03", "scenario-04"]
SCENARIO_LABELS = ["Cenário 1", "Cenário 2", "Cenário 3", "Cenário 4"]

ALGORITHMS = {
    "AES": {
        "encrypt": "aes_encrypt_ms",
        "decrypt": "aes_decrypt_ms",
        "marker": "o",
    },
    "RSA": {
        "encrypt": "rsa_encrypt_ms",
        "decrypt": "rsa_decrypt_ms",
        "marker": "s",
    },
    "ImSecret": {
        "encrypt": "imsecret_encrypt_ms",
        "decrypt": "imsecret_decrypt_ms",
        "marker": "^",
    },
}


def book_name(filename):
    stem = Path(filename).stem
    return re.sub(r"-(01|02|03|04)$", "", stem)


def pretty_name(name):
    return name.replace("-", " ").title()


def save_line_chart(data, operation, title, output):
    plt.figure(figsize=(8, 5))

    for algorithm, config in ALGORITHMS.items():
        values = data[config[operation]].to_numpy()
        plt.plot(SCENARIO_LABELS, values, marker=config["marker"], linewidth=2, markersize=7, label=algorithm)

    plt.xlabel("Cenário")
    plt.ylabel("Tempo médio (ms)")
    plt.yscale("log")
    plt.title(title)
    plt.grid(True, alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output, dpi=200, bbox_inches="tight")
    plt.close()


def plot_books(df, output_dir):
    df = df.copy()
    df["livro"] = df["arquivo"].apply(book_name)

    books_by_scenario = {
        scenario: set(df.loc[df["cenario"] == scenario, "livro"])
        for scenario in SCENARIOS
    }

    common_books = set.intersection(*(books_by_scenario[s] for s in SCENARIOS))

    books_dir = output_dir / "livros"
    books_dir.mkdir(parents=True, exist_ok=True)

    for book in sorted(common_books):
        data = df[df["livro"] == book].copy()
        data["cenario"] = pd.Categorical(data["cenario"], categories=SCENARIOS, ordered=True)
        data = data.sort_values("cenario")

        if len(data) != 4:
            continue

        name = pretty_name(book)

        save_line_chart(
            data,
            "encrypt",
            f"Criptografia — {name}",
            books_dir / f"{book}_encrypt.png",
        )

        save_line_chart(
            data,
            "decrypt",
            f"Decriptografia — {name}",
            books_dir / f"{book}_decrypt.png",
        )

    return len(common_books)


def plot_scenario_throughput(df, output_dir):
    rows = []

    for scenario in SCENARIOS:
        data = df[df["cenario"] == scenario]
        total_bytes = data["tamanho_bytes"].sum()
        row = {"cenario": scenario}

        for algorithm, config in ALGORITHMS.items():
            for operation in ("encrypt", "decrypt"):
                total_ms = data[config[operation]].sum()
                row[f"{algorithm}_{operation}"] = (total_bytes / 1_000_000) / (total_ms / 1000)

        rows.append(row)

    throughput = pd.DataFrame(rows)

    for operation, title, filename in (
        ("encrypt", "Throughput médio de criptografia por cenário", "media_cenarios_encrypt.png"),
        ("decrypt", "Throughput médio de decriptografia por cenário", "media_cenarios_decrypt.png"),
    ):
        plt.figure(figsize=(8, 5))

        for algorithm, config in ALGORITHMS.items():
            plt.plot(
                SCENARIO_LABELS,
                throughput[f"{algorithm}_{operation}"],
                marker=config["marker"],
                linewidth=2,
                markersize=7,
                label=algorithm,
            )

        plt.xlabel("Cenário")
        plt.ylabel("Throughput (MB/s)")
        plt.yscale("log")
        plt.title(title)
        plt.grid(True, alpha=0.25)
        plt.legend()
        plt.tight_layout()
        plt.savefig(output_dir / filename, dpi=200, bbox_inches="tight")
        plt.close()


def main():
    parser = argparse.ArgumentParser(description="Gera gráficos dos benchmarks AES, RSA e ImSecret.")
    parser.add_argument("csv", nargs="?", default="resultados.csv", help="CSV gerado pelo benchmark.sh")
    parser.add_argument("-o", "--output", default="graficos", help="Diretório onde os PNGs serão salvos")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    output_dir = Path(args.output)

    if not csv_path.is_file():
        raise SystemExit(f"CSV não encontrado: {csv_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)

    required = {"cenario", "arquivo", "tamanho_bytes"}
    for config in ALGORITHMS.values():
        required.add(config["encrypt"])
        required.add(config["decrypt"])

    missing = required - set(df.columns)
    if missing:
        raise SystemExit("Colunas ausentes no CSV: " + ", ".join(sorted(missing)))

    books = plot_books(df, output_dir)
    plot_scenario_throughput(df, output_dir)

    print(f"Gráficos gerados em: {output_dir}")
    print(f"Livros presentes nos quatro cenários: {books}")


if __name__ == "__main__":
    main()
