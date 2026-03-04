use clap::{Parser, Subcommand, CommandFactory};
use std::path::PathBuf;

mod encriptador;
mod desencriptador;
mod utils;

/// 🔐 Encriptador Profesional para Linux
/// Versión: 1.0 - Hecho en Rust 🦀
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Modo verbose (más detalles)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Sin colores en la salida
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Encriptar archivos o carpetas
    Encriptar {
        /// Archivo(s) a encriptar
        #[arg(required = true)]
        archivos: Vec<PathBuf>,

        /// Contraseña (si no se provee, se pedirá interactivamente)
        #[arg(short, long)]
        password: Option<String>,

        /// Directorio de salida
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Algoritmo de encriptación [aes256]
        #[arg(short, long, default_value = "aes256")]
        algoritmo: String,

        /// Comprimir antes de encriptar
        #[arg(short, long)]
        comprimir: bool,

        /// Nivel de compresión (1-9)
        #[arg(long, default_value_t = 6)]
        nivel_compresion: u8,

        /// Encriptar recursivamente carpetas
        #[arg(short, long)]
        recursivo: bool,

        /// Número de hilos
        #[arg(short, long)]
        hilos: Option<usize>,

        /// Verificar integridad después de encriptar
        #[arg(long)]
        verificar: bool,

        /// Borrar archivos originales después de encriptar
        #[arg(long)]
        borrar_original: bool,
    },

    /// Desencriptar archivos
    Desencriptar {
        /// Archivo(s) a desencriptar
        #[arg(required = true)]
        archivos: Vec<PathBuf>,

        /// Contraseña
        #[arg(short, long)]
        password: Option<String>,

        /// Directorio de salida
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Verificar integridad
        #[arg(long)]
        verificar: bool,
    },

    /// Ver información de archivos encriptados
    Info {
        /// Archivo(s) a analizar
        #[arg(required = true)]
        archivos: Vec<PathBuf>,

        /// Mostrar información detallada
        #[arg(short, long)]
        detallado: bool,
    },

    /// Generar autocompletado para el shell
    Completions {
        /// Shell: bash, zsh, fish
        shell: clap_complete::Shell,
    },

    /// Ejecutar pruebas de rendimiento
    Benchmark {
        /// Tamaño del archivo de prueba en MB
        #[arg(short, long, default_value_t = 100)]
        tamano: usize,

        /// Número de iteraciones
        #[arg(short, long, default_value_t = 5)]
        iteraciones: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    if !cli.verbose {
        utils::mostrar_banner();
    }

    match &cli.command {
        Commands::Encriptar { archivos, password, output, algoritmo, comprimir, nivel_compresion, recursivo, hilos, verificar, borrar_original } => {
            encriptador::encriptar(
                archivos, password, output, algoritmo, 
                *comprimir, *nivel_compresion, *recursivo, 
                *hilos, *verificar, *borrar_original
            )?;
        }
        Commands::Desencriptar { archivos, password, output, verificar } => {
            desencriptador::desencriptar(archivos, password, output, *verificar)?;
        }
        Commands::Info { archivos, detallado } => {
            utils::mostrar_info(archivos, *detallado)?;
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(*shell, &mut cmd, "encriptador", &mut std::io::stdout());
        }
        Commands::Benchmark { tamano, iteraciones } => {
            utils::benchmark(*tamano, *iteraciones)?;
        }
    }

    Ok(())
}
