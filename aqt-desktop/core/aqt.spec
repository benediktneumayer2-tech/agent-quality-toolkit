# PyInstaller spec of the frozen AQT runtime: one folder (onedir, no unpacking at each start) with the
# program `aqt` and every package of the toolkit. Build it with core/build.sh.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

PACKAGES = ["aqt_evidence", "aqt_trail", "aqt_signoff", "aqt_change", "aqt_sensei", "aqt_quarantine",
            "aqt_validate", "aqt_capa", "aqt_ui", "aqt_cli", "aqt_egress"]
DISTRIBUTIONS = ["aqt-spec", "aqt-trail", "aqt-signoff", "aqt-change", "aqt-sensei", "aqt-quarantine",
                 "aqt-validate", "aqt-capa", "aqt-ui", "agent-quality-toolkit", "aqt-egress"]

hidden = [module for package in PACKAGES for module in collect_submodules(package)]
hidden += collect_submodules("mitmproxy")        # addons and content views are imported by name
# data files: aqt-ui static, aqt-spec schemas, vectors and catalogues, templates, prompts, thresholds;
# aqt-sensei copies its agent.py into the sandbox, so its sources come along as files too
datas = [item for package in PACKAGES for item in collect_data_files(package)]
datas += collect_data_files("aqt_sensei", include_py_files=True)
datas += collect_data_files("mitmproxy")
# versions and entry points (aqt.detectors) are read through importlib.metadata
datas += [item for dist in DISTRIBUTIONS for item in copy_metadata(dist)]

a = Analysis(["aqt_entry.py"], hiddenimports=hidden, datas=datas, excludes=["tkinter"], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="aqt", console=True, upx=False, strip=False)
coll = COLLECT(exe, a.binaries, a.datas, name="aqt", upx=False, strip=False)
