# -*- mode: python ; coding: utf-8 -*-


block_cipher = None

added_files = [
         ( 'D:\Coding\VSCode\PassCrate/iconadd.png', '.' ),
         ( 'D:\Coding\VSCode\PassCrate/iconpencil.png', '.' ),
	 ( 'D:\Coding\VSCode\PassCrate/icontrash.png', '.' ),
	 ( 'D:\Coding\VSCode\PassCrate/keyicon.ico', '.' )
         ]


a = Analysis(
    ['PassCrate1.0.py', 'PassCrate1.0.spec'],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PassCrate1.0',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
