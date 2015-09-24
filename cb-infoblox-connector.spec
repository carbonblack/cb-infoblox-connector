# -*- mode: python -*-
a = Analysis(['scripts/cb-infoblox-connector'],
             pathex=['.'],
             hiddenimports=['unicodedata', 'google'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='cb-infoblox-connector',
          debug=False,
          strip=False,
          upx=True,
          console=True )
