# pentoolbox.spec
# Lance avec : pyinstaller pentoolbox.spec

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['app/app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('reports', 'reports'),
    ],
    hiddenimports=[
        'flask', 'flask_cors', 'jinja2', 'werkzeug',
        'dns', 'dns.resolver', 'dns.rdatatype',
        'engineio', 'socketio',
    ],
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
    name='PenToolbox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # False = pas de fenêtre terminal (mode silencieux)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,             # Mets ici le chemin vers un .ico si tu veux une icône
)
