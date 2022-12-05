if ($psise) {
	$root = Split-Path $psise.CurrentFile.FullPath
}
else {
	$root = $PSScriptRoot
}

&$root/.env/Scripts/python $root/src/nordscan.py $args
