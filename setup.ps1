if ($psise) {
	$root = Split-Path $psise.CurrentFile.FullPath
}
else {
	$root = $PSScriptRoot
}

python -m venv $root\.env
&$root\.env\scripts\activate.ps1
pip install --upgrade pip
pip install wheel
pip install -r $root/requirements-windows.txt
deactivate
