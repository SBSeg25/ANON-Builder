import pandas as pd
import matplotlib.pyplot as plt
import os
import altair as alt
import sys
import argparse

OUTPUT_DIR = "analysis_results"

def comparacao_cwe_analysis(
    baseline_path,
    categorizado_path,
):
    # Carregar os datasets
    df_base = pd.read_csv(baseline_path, dtype=str)
    df_cat = pd.read_csv(categorizado_path, dtype=str)

    # Filtrar apenas fonte NVD
    df_base = df_base[df_base['source'] == 'nvd']
    df_cat = df_cat[df_cat['source'] == 'nvd']

    # Selecionar apenas as colunas relevantes
    df_base = df_base[['id', 'cwe_category']]
    df_cat = df_cat[['id', 'cwe_category']]

    # Remover baseline com múltiplas categorias (apenas uma categoria)
    df_base = df_base[df_base['cwe_category'].notna()]
    df_base = df_base[~df_base['cwe_category'].str.contains(',')]

    # Remover baseline com "NVD-CWE-Other" e "NVD-CWE-noinfo"
    filtros = ["NVD-CWE-Other", "NVD-CWE-noinfo"]
    df_base = df_base[~df_base['cwe_category'].isin(filtros)]

    # Remover do comparado os CVEs que estão na baseline removida
    ids_validos = set(df_base['id'])
    df_cat = df_cat[df_cat['id'].isin(ids_validos)]

    # Juntar os datasets filtrados pelo id
    df_merged = pd.merge(df_base, df_cat, on='id', suffixes=('_base', '_cat'), how='inner')

    # Comparação direta
    df_merged['acerto'] = df_merged['cwe_category_base'] == df_merged['cwe_category_cat']

    # Salvar CSV com os dados comparados
    df_merged_out = df_merged.rename(columns={
        'id': 'CVE_ID_BASELINE',
        'cwe_category_base': 'CWE_CATEGORY_BASELINE',
        'cwe_category_cat': 'CWE_CATEGORY_CATEGORIZED'
    })
    df_merged_out['CVE_ID_BASELINE_CATEGORIZED'] = df_merged_out['CVE_ID_BASELINE']

    df_merged_out = df_merged_out[
        ['CVE_ID_BASELINE', 'CWE_CATEGORY_BASELINE', 'CVE_ID_BASELINE_CATEGORIZED', 'CWE_CATEGORY_CATEGORIZED']
    ]

    result = (
        df_merged.groupby('cwe_category_base')['acerto']
        .agg(['count', 'sum'])
        .rename(columns={'count': 'total', 'sum': 'acertos'})
    )
    result['porcentagem'] = 100 * result['acertos'] / result['total']

    print("=== Comparação Direta (apenas NVD, baseline com uma categoria) ===")
    print(result.reset_index())
    total = result['total'].sum()
    acertos = result['acertos'].sum()
    print(f'\nPorcentagem geral de acertos: {100 * acertos / total:.2f}%')
    print(f'Total de categorias únicas: {result.shape[0]}')
    print(f'Total de CVEs comparados: {df_merged.shape[0]}')



def analyze_dataset(csv_file):
    dataset_name = os.path.splitext(os.path.basename(csv_file))[0]
    dataset_output_dir = os.path.join(OUTPUT_DIR, dataset_name)
    os.makedirs(dataset_output_dir, exist_ok=True)
    log_file_path = os.path.join(dataset_output_dir, f"{dataset_name}_analysis.txt")
    log_file = open(log_file_path, "w", encoding="utf-8")

    df = pd.read_csv(csv_file, sep=',', encoding='latin1')
    df.replace("Unknown", "Desconhecido", inplace=True)

    # Garante que a coluna 'published' existe e converte para datetime
    if 'published' in df.columns:
        df['published'] = pd.to_datetime(df['published'], errors='coerce')
    else:
        df['published'] = pd.NaT

    # Só cria colunas de data se published for datetime
    if pd.api.types.is_datetime64_any_dtype(df['published']):
        df['year'] = df['published'].dt.year
        df['month'] = df['published'].dt.month
        df['day_of_week'] = df['published'].dt.day_name()
        df['quarter'] = df['published'].dt.quarter
    else:
        df['year'] = None
        df['month'] = None
        df['day_of_week'] = None
        df['quarter'] = None

    log_file.write(f"Análise do dataset: {csv_file}\n\n")
    total_vulnerabilities = len(df)
    log_file.write(f"Total de Vulnerabilidades: {total_vulnerabilities}\n")

    # --- Distribuição por Fornecedor e Fonte ---
    vendor_counts = df['vendor'].value_counts()
    source_counts = df['source'].value_counts()
    log_file.write("\nVulnerabilidades por Fornecedor:\n")
    log_file.write(vendor_counts.to_string() + "\n")
    log_file.write("\nVulnerabilidades por Fonte de Dados (source):\n")
    log_file.write(source_counts.to_string() + "\n")

    # --- Comparativo: Severidade por Fonte ---
    log_file.write("\nDistribuição de Severidade por Fonte:\n")
    severity_by_source = pd.crosstab(df['source'], df['severity'])
    log_file.write(severity_by_source.to_string() + "\n")

    # --- Comparativo: CVSS médio por Fonte e por Vendor ---
    log_file.write("\nCVSS Score Médio por Fonte:\n")
    cvss_by_source = df.groupby('source')['cvss_score'].mean()
    log_file.write(cvss_by_source.to_string() + "\n")
    log_file.write("\nCVSS Score Médio por Fornecedor:\n")
    cvss_by_vendor = df.groupby('vendor')['cvss_score'].mean()
    log_file.write(cvss_by_vendor.to_string() + "\n")

    # --- Top CWE por Fonte ---
    log_file.write("\nTop 3 CWE por Fonte:\n")
    for src in df['source'].unique():
        top_cwe = df[df['source'] == src]['cwe_category'].value_counts().head(3)
        log_file.write(f"\nFonte: {src}\n")
        log_file.write(top_cwe.to_string() + "\n")

    # --- Relatório: Vendor, Fonte, Quantidade de CWEs e Quais CWEs ---
    log_file.write("\nRelação de Vendor, Fonte, Quantidade de CWEs e Quais CWEs:\n")
    vendor_source_cwe = (
        df.groupby(['vendor', 'source'])['cwe_category']
        .agg(['nunique', lambda x: ', '.join(sorted(x.dropna().unique()))])
        .reset_index()
        .rename(columns={'nunique': 'quantidade_cwes', '<lambda_0>': 'cwes'})
    )
    for _, row in vendor_source_cwe.iterrows():
        v = row['vendor']
        s = row['source']
        q = row['quantidade_cwes']
        cwes = row['cwes']
        log_file.write(f"\nVendor: {v}\nFonte: {s}\nQuantidade de CWEs: {q}\nCWEs: {cwes}\n")

    # --- Relatório: Vendor, Fonte, Quantidade de Vulnerabilidades ---
    log_file.write("\nRelação de Vendor, Fonte e Quantidade de Vulnerabilidades:\n")
    vendor_source_vuln = (
        df.groupby(['vendor', 'source'])
        .size()
        .reset_index(name='quantidade_vulnerabilidades')
    )
    for _, row in vendor_source_vuln.iterrows():
        v = row['vendor']
        s = row['source']
        q = row['quantidade_vulnerabilidades']
        log_file.write(f"\nVendor: {v}\nFonte: {s}\nQuantidade de Vulnerabilidades: {q}\n") 

    # --- Tabela cruzada: Vendor x Fonte ---
    log_file.write("\nTabela cruzada: Vendor x Fonte:\n")
    vendor_source_table = pd.crosstab(df['vendor'], df['source'])
    log_file.write(vendor_source_table.to_string() + "\n")

    # --- Gráficos comparativos ---
    font_size = 18

# Tradução dos termos para português
    severity_translate = {
        "CRITICAL": "CRÍTICA",
        "HIGH": "ALTA",
        "MEDIUM": "MÉDIA",
        "LOW": "BAIXA",
        "NONE": "NENHUMA",
        "UNKNOWN": "DESCONHECIDA"
    }
    df['severity'] = df['severity'].replace(severity_translate)

    # Ordem desejada para as severidades em português
    severity_order = ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "NENHUMA", "DESCONHECIDA"]

    # Vulnerabilidades por Fonte
    plt.figure(figsize=(8, 6))
    source_counts.plot(kind='bar', color='skyblue')
    plt.title("Vulnerabilidades por Fonte de Dados", fontsize=font_size)
    plt.xlabel("Fonte", fontsize=font_size)
    plt.ylabel("Número de Vulnerabilidades", fontsize=font_size)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(dataset_output_dir, "vulnerabilities_by_source.png"))
    plt.close()

    # CVSS Score médio por Fonte
    plt.figure(figsize=(8, 6))
    cvss_by_source.plot(kind='bar', color='orange')
    plt.title("CVSS Score Médio por Fonte", fontsize=font_size)
    plt.xlabel("Fonte", fontsize=font_size)
    plt.ylabel("CVSS Score Médio", fontsize=font_size)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(dataset_output_dir, "cvss_by_source.png"))
    plt.close()

    # CVSS Score médio por Vendor (top 10)
    plt.figure(figsize=(10, 6))
    cvss_by_vendor.sort_values(ascending=False).head(10).plot(kind='bar', color='green')
    plt.title("Top 10 Vendors por CVSS Score Médio", fontsize=font_size)
    plt.xlabel("Vendor", fontsize=font_size)
    plt.ylabel("CVSS Score Médio", fontsize=font_size)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(dataset_output_dir, "cvss_by_vendor_top10.png"))
    plt.close()

    # Severidade por Fonte (stacked bar)
    severity_by_source = pd.crosstab(df['source'], df['severity'])
    severity_by_source = severity_by_source.reindex(columns=severity_order, fill_value=0)
    severity_by_source.plot(kind='bar', stacked=True, figsize=(10, 6))
    plt.title("Distribuição de Severidade por Fonte", fontsize=font_size)
    plt.xlabel("Fonte", fontsize=font_size)
    plt.ylabel("Número de Vulnerabilidades", fontsize=font_size)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(dataset_output_dir, "distribuicao_severidade_por_fonte.png"))
    plt.close()

    # Fechar o arquivo de log
    log_file.close()

def comparative_analysis(csv_files):
    # Carrega todos os datasets e faz análise comparativa entre eles
    dfs = []
    names = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file, sep=',', encoding='latin1')
        df['dataset'] = os.path.splitext(os.path.basename(csv_file))[0]
        dfs.append(df)
        names.append(df['dataset'].iloc[0])
    all_df = pd.concat(dfs, ignore_index=True)

    # Comparativo: Vendors em comum e exclusivos
    vendors_by_dataset = all_df.groupby('dataset')['vendor'].unique()
    print("\nVendors por dataset:")
    for name, vendors in vendors_by_dataset.items():
        print(f"{name}: {set(vendors)}")
    common_vendors = set.intersection(*(set(v) for v in vendors_by_dataset))
    print(f"\nVendors em comum: {common_vendors}")

    # Comparativo: Fontes em comum e exclusivos
    sources_by_dataset = all_df.groupby('dataset')['source'].unique()
    print("\nFontes por dataset:")
    for name, sources in sources_by_dataset.items():
        print(f"{name}: {set(sources)}")
    common_sources = set.intersection(*(set(s) for s in sources_by_dataset))
    print(f"\nFontes em comum: {common_sources}")

    # Gráfico comparativo: vulnerabilidades por fonte em cada dataset
    import seaborn as sns
    import matplotlib.pyplot as plt
    plt.figure(figsize=(10, 6))
    sns.countplot(data=all_df, x='source', hue='dataset')
    plt.title("Vulnerabilidades por Fonte em cada Dataset")
    plt.xlabel("Fonte")
    plt.ylabel("Número de Vulnerabilidades")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "comparative_vulnerabilities_by_source.png"))
    plt.close()

    # Gráfico comparativo: vulnerabilidades por vendor em cada dataset (top 10 vendors)
    top_vendors = all_df['vendor'].value_counts().head(10).index
    plt.figure(figsize=(12, 6))
    sns.countplot(data=all_df[all_df['vendor'].isin(top_vendors)], x='vendor', hue='dataset')
    plt.title("Top 10 Vendors - Vulnerabilidades por Dataset")
    plt.xlabel("Vendor")
    plt.ylabel("Número de Vulnerabilidades")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "comparative_vulnerabilities_by_vendor.png"))
    plt.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Análise de datasets de vulnerabilidades.")
    parser.add_argument('csv_files', nargs='*', help='Arquivos CSV para análise individual/comparativa')
    parser.add_argument('--baseline', type=str, help='Arquivo baseline para comparação CWE')
    parser.add_argument('--categorizado', type=str, help='Arquivo categorizado para comparação CWE')
    args = parser.parse_args()

    if args.baseline and args.categorizado:
        comparacao_cwe_analysis(args.baseline, args.categorizado)
        # Você pode adicionar argumentos para os arquivos de saída se desejar

    if args.csv_files:
        for csv_file in args.csv_files:
            analyze_dataset(csv_file)
        if len(args.csv_files) > 1:
            comparative_analysis(args.csv_files)
    elif not (args.baseline and args.categorizado):
        print("Uso:")
        print("  python analysis.py <arquivo_csv1> <arquivo_csv2> ...")
        print("  python analysis.py --baseline BASELINE.csv --categorizado CATEGORIZADO.csv")
        sys.exit(1)