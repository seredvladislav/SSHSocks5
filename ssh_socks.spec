# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['ssh_socks.py'],
             pathex=[''],
              excludes=[
                'FixTk', 'tcl', 'tk', '_tkinter', 'tkinter', 'Tkinter',
            ],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False
             )
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='ssh_socks',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='ssh_socks')
