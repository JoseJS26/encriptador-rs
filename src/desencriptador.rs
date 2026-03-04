use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use colored::*;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};  // IMPORTANTE: Añadir Seek
use std::path::{Path, PathBuf};
use flate2::read::GzDecoder;

use crate::encriptador::MAGIC_BYTES;
use crate::utils;

pub fn desencriptar(
    archivos: &[PathBuf],
    password: &Option<String>,
    output_dir: &Path,
    _verificar: bool,
) -> Result<()> {
    println!("\n{}", "🔓 INICIANDO DESENCRIPTACIÓN".bright_blue().bold());
    println!("{}", "══════════════════════════════".bright_blue());

    let password = match password {
        Some(p) => p.clone(),
        None => utils::pedir_password("Ingresa la contraseña: ")?,
    };

    let mut exitosos = 0;
    let mut fallidos = 0;

    for archivo in archivos {
        println!("\n📄 Procesando: {}", archivo.display());
        
        match desencriptar_archivo(archivo, &password, output_dir) {
            Ok(ruta) => {
                println!("  {} Desencriptado: {}", "✓".green(), ruta.display());
                exitosos += 1;
            }
            Err(e) => {
                println!("  {} Error: {}", "✗".red(), e);
                fallidos += 1;
            }
        }
    }

    println!("\n{}", "══════════════════════════════".bright_blue());
    println!("📊 Resultados: {} exitosos, {} fallidos", exitosos, fallidos);

    Ok(())
}

fn desencriptar_archivo(
    ruta: &Path,
    password: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    let mut archivo = File::open(ruta)?;
    
    // Leer magic bytes
    let mut magic = [0u8; 8];
    archivo.read_exact(&mut magic)?;
    if magic != MAGIC_BYTES {
        return Err(anyhow!("Formato de archivo inválido"));
    }

    // Leer header
    let mut version = [0u8; 1];
    let mut algorithm = [0u8; 1];
    let mut compression = [0u8; 1];
    archivo.read_exact(&mut version)?;
    archivo.read_exact(&mut algorithm)?;
    archivo.read_exact(&mut compression)?;

    // Leer salt (16 bytes binarios)
    let mut salt = [0u8; 16];
    archivo.read_exact(&mut salt)?;
    
    // Leer nonce
    let mut nonce_bytes = [0u8; 12];
    archivo.read_exact(&mut nonce_bytes)?;
    
    // Leer tamaño original
    let mut size_bytes = [0u8; 8];
    archivo.read_exact(&mut size_bytes)?;
    let _original_size = u64::from_be_bytes(size_bytes);
    
    // Leer longitud del nombre
    let mut name_len_bytes = [0u8; 2];
    archivo.read_exact(&mut name_len_bytes)?;
    let name_len = u16::from_be_bytes(name_len_bytes) as usize;
    
    // Leer nombre original
    let mut nombre_bytes = vec![0u8; name_len];
    archivo.read_exact(&mut nombre_bytes)?;
    let nombre_original = String::from_utf8(nombre_bytes)
        .map_err(|_| anyhow!("Nombre de archivo inválido"))?;

    // Leer datos encriptados
    let mut datos_encriptados = Vec::new();
    archivo.read_to_end(&mut datos_encriptados)?;

    // Derivar clave con el mismo método
    let argon2 = Argon2::default();
    let mut hash = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut hash)
        .map_err(|_| anyhow!("Error derivando clave"))?;

    let cipher = Aes256Gcm::new_from_slice(&hash)
        .map_err(|_| anyhow!("Error creando cipher"))?;

    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let datos_desencriptados = cipher.decrypt(nonce, datos_encriptados.as_ref())
        .map_err(|_| anyhow!("Error desencriptando. ¿Contraseña incorrecta?"))?;

    let datos_finales = if compression[0] == 1 {
        descomprimir_datos(&datos_desencriptados)?
    } else {
        datos_desencriptados
    };

    let ruta_salida = output_dir.join(&nombre_original);
    fs::write(&ruta_salida, datos_finales)?;

    Ok(ruta_salida)
}

pub fn desencriptar_en_memoria(ruta: &Path, password: &str) -> Result<Vec<u8>> {
    let mut archivo = File::open(ruta)?;
    let mut datos = Vec::new();
    archivo.read_to_end(&mut datos)?;
    
    let mut cursor = std::io::Cursor::new(&datos);
    
    // Leer magic bytes
    let mut magic = [0u8; 8];
    cursor.read_exact(&mut magic)?;
    
    // Leer header
    let mut version = [0u8; 1];
    let mut algorithm = [0u8; 1];
    let mut compression = [0u8; 1];
    cursor.read_exact(&mut version)?;
    cursor.read_exact(&mut algorithm)?;
    cursor.read_exact(&mut compression)?;

    // Leer salt
    let mut salt = [0u8; 16];
    cursor.read_exact(&mut salt)?;
    
    // Leer nonce
    let mut nonce_bytes = [0u8; 12];
    cursor.read_exact(&mut nonce_bytes)?;
    
    // Leer tamaño original
    let mut size_bytes = [0u8; 8];
    cursor.read_exact(&mut size_bytes)?;
    let _original_size = u64::from_be_bytes(size_bytes);
    
    // Leer longitud del nombre
    let mut name_len_bytes = [0u8; 2];
    cursor.read_exact(&mut name_len_bytes)?;
    let name_len = u16::from_be_bytes(name_len_bytes) as usize;
    
    // Saltar nombre original - AHORA FUNCIONA PORQUE IMPORTAMOS SEEK
    cursor.seek(SeekFrom::Current(name_len as i64))?;
    
    // Leer datos encriptados
    let mut datos_encriptados = Vec::new();
    cursor.read_to_end(&mut datos_encriptados)?;

    // Derivar clave
    let argon2 = Argon2::default();
    let mut hash = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut hash)
        .map_err(|_| anyhow!("Error derivando clave"))?;

    let cipher = Aes256Gcm::new_from_slice(&hash).unwrap();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    
    let datos_desencriptados = cipher.decrypt(nonce, datos_encriptados.as_ref())
        .map_err(|_| anyhow!("Error desencriptando"))?;

    if compression[0] == 1 {
        descomprimir_datos(&datos_desencriptados)
    } else {
        Ok(datos_desencriptados)
    }
}

fn descomprimir_datos(datos: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(datos);
    let mut resultado = Vec::new();
    decoder.read_to_end(&mut resultado)?;
    Ok(resultado)
}
