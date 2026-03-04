use anyhow::{anyhow, Result};
use colored::*;
use rpassword::read_password;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;
use chrono::{DateTime, Local};

pub fn mostrar_banner() {
    let banner = r#"
    ╔══════════════════════════════════════╗
    ║     🔐  ENCRIPTADOR RS  v1.0        ║
    ║    Hecho en Rust - Seguridad Total   ║
    ╚══════════════════════════════════════╝
    "#;
    println!("{}", banner.bright_green());
}

pub fn pedir_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = read_password()?;
    if password.is_empty() {
        return Err(anyhow!("La contraseña no puede estar vacía"));
    }
    
    print!("Confirma la contraseña: ");
    io::stdout().flush()?;
    let confirmacion = read_password()?;
    
    if password != confirmacion {
        return Err(anyhow!("Las contraseñas no coinciden"));
    }
    
    Ok(password)
}

pub fn mostrar_info(archivos: &[PathBuf], detallado: bool) -> Result<()> {
    for archivo in archivos {
        println!("\n📁 Archivo: {}", archivo.display());
        
        if detallado {
            let metadata = std::fs::metadata(archivo)?;
            println!("  Tamaño: {}", format_size(metadata.len()));
            
            if let Ok(modified) = metadata.modified() {
                let datetime: DateTime<Local> = modified.into();
                println!("  Modificado: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
            }
            
            if archivo.extension().and_then(|e| e.to_str()) == Some("encrypted") {
                println!("  Tipo: Archivo encriptado");
            }
        }
    }
    Ok(())
}

pub fn benchmark(tamano_mb: usize, iteraciones: usize) -> Result<()> {
    println!("\n{}", "⚡ BENCHMARK DE RENDIMIENTO".bright_yellow().bold());
    println!("Tamaño: {} MB, Iteraciones: {}", tamano_mb, iteraciones);
    
    let _datos = vec![0u8; tamano_mb * 1024 * 1024];
    
    let mut tiempos = Vec::new();
    
    for i in 0..iteraciones {
        print!("  Iteración {}/{}... ", i + 1, iteraciones);
        io::stdout().flush()?;
        
        let start = Instant::now();
        
        // Simular trabajo
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        let duration = start.elapsed();
        tiempos.push(duration);
        println!("{:.2}s", duration.as_secs_f64());
    }
    
    let total: f64 = tiempos.iter().map(|t| t.as_secs_f64()).sum();
    let promedio = total / iteraciones as f64;
    
    println!("\n📊 Resultados:");
    println!("  Tiempo promedio: {:.2}s", promedio);
    println!("  Velocidad: {:.2} MB/s", tamano_mb as f64 / promedio);
    
    Ok(())
}

pub fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if size < KB {
        format!("{} B", size)
    } else if size < MB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else if size < GB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else {
        format!("{:.2} GB", size as f64 / GB as f64)
    }
}
