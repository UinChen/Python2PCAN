# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['can_monitor_gui.py'],  # 你的主程序文件名
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['can.interfaces.pcan', 'can.interfaces.socketcan', 'can.interfaces.kvaser'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'scipy', 'tkinter.test', 
             'unittest', 'doctest', 'setuptools', 'pkg_resources', 'distutils'],
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
    name='CAN监控工具',  # 生成的可执行文件名称
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # 使用UPX压缩
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 不显示控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
