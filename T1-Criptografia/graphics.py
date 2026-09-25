#!/usr/bin/env python3

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


SCENARIOS = ["scenario-01", "scenario-02", "scenario-03", "scenario-04"]
SCENARIO_LABELS = ["Cenário 1", "Cenário 2", "Cenário 3", "Cenário 4"]

ALGORITHMS = {
    "AES": {"encrypt": "aes_encrypt_ms", "decrypt": "aes_decrypt_ms", "marker": "o", "offset": 8},
    "RSA": {"encrypt": "rsa_encrypt_ms", "decrypt": "rsa_decrypt_ms", "marker": "s", "offset": 16},
    "ImSecret": {"encrypt": "imsecret_encrypt_ms", "decrypt": "imsecret_decrypt_ms", "marker": "^", "offset": -14},
}


def book_name(filename):
    stem = Path(filename).stem
    return re.sub(r"-(01|02|03|04)$", "", stem)


def pretty_name(name):
    return name.replace("-", " ").title()


def format_bytes(value):
    return f"{int(value):,}".replace(",", ".")


def throughput_mb_s(bytes_values, time_ms_values):
    return (bytes_values / 1_000_000) / (time_ms_values / 1000)


def scenario_labels(bytes_values):
    return [f"{scenario}\n({format_bytes(size)} bytes)" for scenario, size in zip(SCENARIO_LABELS, bytes_values)]


def draw_chart(labels, series, ylabel, title, output, unit):
    plt.figure(figsize=(9, 5.5))

    for algorithm, values in series.items():
        config = ALGORITHMS[algorithm]
        plt.plot(labels, values, marker=config["marker"], linewidth=2, markersize=7, label=algorithm)

        for x, value in zip(labels, values):
            plt.annotate(
                f"{value:.3f} {unit}",
                (x, value),
                textcoords="offset points",
                xytext=(0, config["offset"]),
                ha="center",
                fontsize=8,
            )

    plt.xlabel("Cenário")
    plt.ylabel(ylabel)
    plt.yscale("log")
    plt.title(title)
    plt.grid(True, alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output, dpi=200, bbox_inches="tight")
    plt.close()


def save_book_charts(data, book, output_dir):
    name = pretty_name(book)
    labels = scenario_labels(data["tamanho_bytes"].to_numpy())

    for operation, operation_name in (("encrypt", "Criptografia"), ("decrypt", "Decriptografia")):
        time_series = {
            algorithm: data[config[operation]].to_numpy()
            for algorithm, config in ALGORITHMS.items()
        }

        throughput_series = {
            algorithm: throughput_mb_s(data["tamanho_bytes"].to_numpy(), data[config[operation]].to_numpy())
            for algorithm, config in ALGORITHMS.items()
        }

        draw_chart(
            labels,
            time_series,
            "Tempo médio (ms)",
            f"Tempo de {operation_name.lower()} — {name}",
            output_dir / f"{book}_tempo_{operation}.png",
            "ms",
        )

        draw_chart(
            labels,
            throughput_series,
            "Throughput (MB/s)",
            f"Throughput de {operation_name.lower()} — {name}",
            output_dir / f"{book}_throughput_{operation}.png",
            "MB/s",
        )


def plot_books(df, output_dir):
    df = df.copy()
    df["livro"] = df["arquivo"].apply(book_name)

    books_by_scenario = {scenario: set(df.loc[df["cenario"] == scenario, "livro"]) for scenario in SCENARIOS}
    common_books = set.intersection(*(books_by_scenario[scenario] for scenario in SCENARIOS))

    books_dir = output_dir / "livros"
    books_dir.mkdir(parents=True, exist_ok=True)

    for book in sorted(common_books):
        data = df[df["livro"] == book].copy()
        data["cenario"] = pd.Categorical(data["cenario"], categories=SCENARIOS, ordered=True)
        data = data.sort_values("cenario")

        if len(data) != 4:
            continue

        save_book_charts(data, book, books_dir)

    return len(common_books)


def plot_global(df, output_dir):
    rows = []

    for scenario in SCENARIOS:
        data = df[df["cenario"] == scenario]
        total_bytes = data["tamanho_bytes"].sum()
        row = {"cenario": scenario, "total_bytes": total_bytes}

        for algorithm, config in ALGORITHMS.items():
            for operation in ("encrypt", "decrypt"):
                times = data[config[operation]]
                bytes_values = data["tamanho_bytes"]

                row[f"{algorithm}_{operation}_time"] = (times * bytes_values).sum() / total_bytes
                row[f"{algorithm}_{operation}_throughput"] = (total_bytes / 1_000_000) / (times.sum() / 1000)

        rows.append(row)

    global_data = pd.DataFrame(rows)
    labels = scenario_labels(global_data["total_bytes"].to_numpy())

    for operation, operation_name in (("encrypt", "Criptografia"), ("decrypt", "Decriptografia")):
        time_series = {
            algorithm: global_data[f"{algorithm}_{operation}_time"].to_numpy()
            for algorithm in ALGORITHMS
        }
        throughput_series = {
            algorithm: global_data[f"{algorithm}_{operation}_throughput"].to_numpy()
            for algorithm in ALGORITHMS
        }

        draw_chart(
            labels,
            time_series,
            "Tempo médio ponderado (ms)",
            f"Tempo médio ponderado de {operation_name.lower()} por cenário",
            output_dir / f"global_tempo_{operation}.png",
            "ms",
        )

        draw_chart(
            labels,
            throughput_series,
            "Throughput (MB/s)",
            f"Throughput global de {operation_name.lower()} por cenário",
            output_dir / f"global_throughput_{operation}.png",
            "MB/s",
        )


def main():
    parser = argparse.ArgumentParser(description="Gera gráficos de tempo e throughput para AES, RSA e ImSecret.")
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

    if (df["tamanho_bytes"] <= 0).any():
        raise SystemExit("O CSV contém tamanho_bytes menor ou igual a zero.")

    time_columns = [config[operation] for config in ALGORITHMS.values() for operation in ("encrypt", "decrypt")]
    if (df[time_columns] <= 0).any().any():
        raise SystemExit("A escala logarítmica exige tempos maiores que zero.")

    books = plot_books(df, output_dir)
    plot_global(df, output_dir)

    print(f"Gráficos gerados em: {output_dir}")
    print(f"Livros presentes nos quatro cenários: {books}")


if __name__ == "__main__":
    main()
