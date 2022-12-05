# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['src/nordscan.py'],
             pathex=['.env/Lib/site-packages', 'src'],
             binaries=[],
             datas=[('src/plugins', 'plugins'), ('src/scripts', 'scripts')],
             hiddenimports=['ssh2.session','ssh2.agent', 'ssh2.pkey', 'ssh2.exceptions', 'ssh2.sftp', 'ssh2.sftp_handle', 'ssh2.channel', 'ssh2.listener', 'ssh2.statinfo', 'ssh2.knownhost', 'ssh2.error_codes', 'ssh2.fileinfo', 'ssh2.utils', 'ssh2.publickey','plugins.input.ssh','plugins.input.winrm','plugins.input.snmp','plugins.output.logstash'],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts, 
          [],
          exclude_binaries=True,
          name='nordscan',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas, 
               strip=False,
               upx=True,
               upx_exclude=[],
               name='nordscan')
