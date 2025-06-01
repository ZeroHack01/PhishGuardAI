const fs = require('fs').promises;
const path = require('path');
const archiver = require('archiver');
const chalk = require('chalk');

const log = {
  cyan: (msg) => console.log(chalk.cyan.bold(`[PhishGuardAI Build] ${msg}`)),
  magenta: (msg) => console.log(chalk.magenta.bold(`[PhishGuardAI Build] ${msg}`)),
  green: (msg) => console.log(chalk.green.bold(`[PhishGuardAI Build] ${msg}`)),
  red: (msg) => console.log(chalk.red.bold(`[PhishGuardAI Build] ${msg}`))
};

async function createBuildDir(buildDir) {
  log.cyan(`Creating build directory: ${buildDir}`);
  try {
    await fs.rm(buildDir, { recursive: true, force: true });
    await fs.mkdir(buildDir, { recursive: true });
    log.green('Build directory created');
  } catch (error) {
    log.red(`Error creating build directory: ${error.message}`);
    throw error;
  }
}

async function copyFiles(srcDir, destDir, files) {
  log.cyan(`Copying files to ${destDir}`);
  try {
    await fs.mkdir(destDir, { recursive: true });
    for (const file of files) {
      const srcPath = path.join(srcDir, file);
      const destPath = path.join(destDir, file);
      await fs.copyFile(srcPath, destPath);
      log.magenta(`Copied ${file}`);
    }
    log.green('File copying completed');
  } catch (error) {
    log.red(`Error copying files: ${error.message}`);
    throw error;
  }
}

async function copyDirectory(srcDir, destDir) {
  log.cyan(`Copying directory: ${srcDir} to ${destDir}`);
  try {
    await fs.mkdir(destDir, { recursive: true });
    const entries = await fs.readdir(srcDir, { withFileTypes: true });
    for (const entry of entries) {
      const srcPath = path.join(srcDir, entry.name);
      const destPath = path.join(destDir, entry.name);
      if (entry.isDirectory()) {
        await copyDirectory(srcPath, destPath);
      } else {
        await fs.copyFile(srcPath, destPath);
        log.magenta(`Copied ${entry.name}`);
      }
    }
    log.green(`Directory ${srcDir} copied`);
  } catch (error) {
    log.red(`Error copying directory: ${error.message}`);
    throw error;
  }
}

async function createZip(buildDir, outputPath) {
  log.cyan(`Creating ZIP archive: ${outputPath}`);
  return new Promise((resolve, reject) => {
    const output = require('fs').createWriteStream(outputPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    output.on('close', () => {
      log.green(`ZIP created: ${archive.pointer()} bytes`);
      resolve();
    });

    archive.on('error', (error) => {
      log.red(`Error creating ZIP: ${error.message}`);
      reject(error);
    });

    archive.pipe(output);
    archive.directory(buildDir, false);
    archive.finalize();
  });
}

async function buildExtension() {
  const rootDir = path.resolve(__dirname, '../..');
  const buildDir = path.join(rootDir, 'build');
  const outputZip = path.join(rootDir, 'phishguardai.zip');

  try {
    // Create build directory
    await createBuildDir(buildDir);

    // Copy root files
    const rootFiles = ['manifest.json'];
    await copyFiles(rootDir, buildDir, rootFiles);

    // Copy directories
    const directories = [
      'popup',
      'content',
      'background',
      'models',
      'threat-intel',
      'icons'
    ];
    for (const dir of directories) {
      await copyDirectory(
        path.join(rootDir, dir),
        path.join(buildDir, dir)
      );
    }

    // Create ZIP archive
    await createZip(buildDir, outputZip);

    log.green('Build completed successfully');
  } catch (error) {
    log.red('Build failed');
    throw error;
  }
}

buildExtension().catch(error => {
  log.red(`Build process terminated: ${error.message}`);
  process.exit(1);
});
