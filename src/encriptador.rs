use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand::RngCore;  // Para fill()
use rand::Rng;      // IMPORTANTE: Para usar el trait Rng
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::desencriptador;
use crate::utils;

pub const MAGIC_BYTES: [u8; 8] = *b"ENCRYPT1";

pub fn encriptar(
    archivos: &[PathBuf],
    password: &Option<String>,
    output_dir: &Path,
    _algoritmo: &str,
    comprimir: bool,
    nivel_compresion: u8,
    recursivo: bool,
    hilos: Option<usize>,
    verificar: bool,
    borrar_original: bool,
) -> Result<()> {
    println!("\n{}", "🔐 INICIANDO ENCRIPTACIÓN".bright_green().bold());
    println!("{}", "══════════════════════════════".bright_green());

    if let Some(h) = hilos {
        rayon::ThreadPoolBuilder::new()
            .num_threads(h)
            .build_global()
            .unwrap();
    }

    let password = match password {
        Some(p) => p.clone(),
        None => utils::pedir_password("Ingresa la contraseña: ")?,
    };

    let mut archivos_a_procesar = Vec::new();
    for archivo in archivos {
        if archivo.is_file() {
            archivos_a_procesar.push(archivo.clone());
        } else if archivo.is_dir() && recursivo {
            for entry in WalkDir::new(archivo)
                .into_iter()
                .filter_entry(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    archivos_a_procesar.push(entry.path().to_path_buf());
                }
            }
        } else if archivo.is_dir() && !recursivo {
            return Err(anyhow!("{} es un directorio. Usa --recursivo para encriptar carpetas", archivo.display()));
        }
    }

    if archivos_a_procesar.is_empty() {
        return Err(anyhow!("No se encontraron archivos para encriptar"));
    }

    println!("📦 Archivos a encriptar: {}", archivos_a_procesar.len());
    println!("🔑 Algoritmo: AES-256-GCM");
    println!("🗜️  Compresión: {}", if comprimir { format!("Sí (nivel {})", nivel_compresion) } else { "No".to_string() });
    println!("");

    let multi = MultiProgress::new();
    let style = ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
        .unwrap()
        .progress_chars("#>-");

    let start = Instant::now();
    let resultados: Vec<Result<PathBuf>> = archivos_a_procesar
        .par_iter()
        .map(|archivo| {
            let pb = multi.add(ProgressBar::new(100));
            pb.set_style(style.clone());
            pb.set_message(format!("{}", archivo.file_name().unwrap().to_string_lossy()));

            let resultado = encriptar_archivo(
                archivo,
                &password,
                output_dir,
                comprimir,
                nivel_compresion,
                &pb,
                verificar,
            );

            pb.finish_with_message(format!("✓ {}", archivo.file_name().unwrap().to_string_lossy()));
            resultado
        })
        .collect();

    let _ = multi.clear();

    let mut exitosos = 0;
    let mut fallidos = 0;

    for resultado in resultados {
        match resultado {
            Ok(path) => {
                println!("{} {}", "✓".green(), path.display());
                if borrar_original {
                    if let Some(original) = archivos_a_procesar.iter().find(|&p| {
                        let nombre_original = p.file_name().unwrap().to_string_lossy();
                        let nombre_encriptado = path.file_name().unwrap().to_string_lossy();
                        nombre_encriptado.starts_with(&*nombre_original)
                    }) {
                        let _ = fs::remove_file(original);
                        println!("  {} Original borrado", "🗑️".yellow());
                    }
                }
                exitosos += 1;
            }
            Err(e) => {
                println!("{} {}", "✗".red(), e);
                fallidos += 1;
            }
        }
    }

    let duration = start.elapsed();
    println!("\n{}", "══════════════════════════════".bright_green());
    println!(
        "{} Encriptación completada en {:.2}s",
        "✅".bright_green(),
        duration.as_secs_f64()
    );
    println!("📊 Resultados: {} exitosos, {} fallidos", exitosos, fallidos);

    Ok(())
}

fn encriptar_archivo(
    ruta: &Path,
    password: &str,
    output_dir: &Path,
    comprimir: bool,
    nivel_compresion: u8,
    pb: &ProgressBar,
    verificar: bool,
) -> Result<PathBuf> {
    pb.set_message("Preparando...");
    
    let datos_originales = fs::read(ruta)
        .with_context(|| format!("No se puede leer {}", ruta.display()))?;
    
    let nombre_original = ruta.file_name()
        .ok_or_else(|| anyhow!("Nombre de archivo inválido"))?
        .to_string_lossy()
        .to_string();

    let datos_a_encriptar = if comprimir {
        pb.set_message("Comprimiendo...");
        comprimir_datos(&datos_originales, nivel_compresion)?
    } else {
        datos_originales.clone()
    };

    pb.set_message("Derivando clave...");
    
    // Generar salt (16 bytes aleatorios)
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);  // Ahora funciona porque importamos rand::Rng
    
    let argon2 = Argon2::default();
    
    // Derivar clave usando el salt binario
    let mut hash = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut hash)
        .map_err(|e| anyhow!("Error derivando clave: {}", e))?;
    
    let cipher = Aes256Gcm::new_from_slice(&hash)
        .map_err(|_| anyhow!("Error creando cipher"))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    pb.set_message("Encriptando...");
    
    let ciphertext = cipher.encrypt(&nonce, datos_a_encriptar.as_ref())
        .map_err(|e| anyhow!("Error encriptando: {}", e))?;

    let nombre_salida = if comprimir {
        format!("{}.encrypted.z", nombre_original)
    } else {
        format!("{}.encrypted", nombre_original)
    };
    
    let ruta_salida = output_dir.join(nombre_salida);
    let mut archivo_salida = File::create(&ruta_salida)?;

    // Escribir header en formato binario
    archivo_salida.write_all(&MAGIC_BYTES)?;           // 8 bytes
    archivo_salida.write_all(&[1u8])?;                 // 1 byte version
    archivo_salida.write_all(&[1u8])?;                 // 1 byte algorithm
    archivo_salida.write_all(&[if comprimir { 1 } else { 0 }])?; // 1 byte compression
    
    archivo_salida.write_all(&salt)?;                  // 16 bytes salt
    archivo_salida.write_all(&nonce)?;                 // 12 bytes nonce
    
    archivo_salida.write_all(&(datos_originales.len() as u64).to_be_bytes())?; // 8 bytes tamaño
    
    let nombre_bytes = nombre_original.as_bytes();
    archivo_salida.write_all(&(nombre_bytes.len() as u16).to_be_bytes())?; // 2 bytes longitud nombre
    archivo_salida.write_all(nombre_bytes)?;           // N bytes nombre
    
    archivo_salida.write_all(&ciphertext)?;            // resto datos encriptados

    pb.set_message("Verificando...");
    
    if verificar {
        let verificacion = desencriptador::desencriptar_en_memoria(&ruta_salida, password)?;
        if verificacion != datos_originales {
            return Err(anyhow!("Error de verificación: los datos no coinciden"));
        }
    }

    pb.set_message("Completado");
    pb.finish();

    Ok(ruta_salida)
}

fn comprimir_datos(datos: &[u8], nivel: u8) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(nivel.into()));
    encoder.write_all(datos)?;
    Ok(encoder.finish()?)
}
