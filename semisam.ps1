Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# === Form Setup ===
$form = New-Object System.Windows.Forms.Form
$form.Text = "💀 Terminal Executor"
$form.Size = New-Object System.Drawing.Size(720, 520)
$form.StartPosition = "CenterScreen"
$form.BackColor = 'Black'
$form.ForeColor = 'Lime'
$form.Font = New-Object System.Drawing.Font("Consolas", 10)

# === Title Label ===
$label = New-Object System.Windows.Forms.Label
$label.Text = ">>> Enter Command:"
$label.AutoSize = $true
$label.ForeColor = 'Lime'
$label.Location = New-Object System.Drawing.Point(15, 15)
$form.Controls.Add($label)

# === Input Box ===
$inputBox = New-Object System.Windows.Forms.TextBox
$inputBox.Multiline = $true
$inputBox.ScrollBars = "Vertical"
$inputBox.BackColor = 'Black'
$inputBox.ForeColor = 'Lime'
$inputBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$inputBox.BorderStyle = "FixedSingle"
$inputBox.Size = New-Object System.Drawing.Size(670, 90)
$inputBox.Location = New-Object System.Drawing.Point(15, 35)
$form.Controls.Add($inputBox)

# === Run Button ===
$runButton = New-Object System.Windows.Forms.Button
$runButton.Text = "RUN"
$runButton.Size = New-Object System.Drawing.Size(80, 35)
$runButton.Location = New-Object System.Drawing.Point(15, 135)
$runButton.BackColor = 'Black'
$runButton.ForeColor = 'Lime'
$runButton.FlatStyle = 'Flat'
$runButton.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
$runButton.FlatAppearance.BorderColor = 'Lime'
$runButton.FlatAppearance.BorderSize = 1
$form.Controls.Add($runButton)

$inputBox.Add_KeyDown({
    if ($_.KeyCode -eq "Enter" -and !$_.Shift) {
        $_.SuppressKeyPress = $true  # Prevents newline
        $runButton.PerformClick()
    }
})


# === Cancel Button ===
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "EXIT"
$cancelButton.Size = New-Object System.Drawing.Size(80, 35)
$cancelButton.Location = New-Object System.Drawing.Point(105, 135)
$cancelButton.BackColor = 'Black'
$cancelButton.ForeColor = 'Red'
$cancelButton.FlatStyle = 'Flat'
$cancelButton.Font = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Bold)
$cancelButton.FlatAppearance.BorderColor = 'Red'
$cancelButton.FlatAppearance.BorderSize = 1
$cancelButton.Add_Click({ $form.Close() })
$form.Controls.Add($cancelButton)

# === Output Label ===
$outputLabel = New-Object System.Windows.Forms.Label
$outputLabel.Text = ">>> Output:"
$outputLabel.AutoSize = $true
$outputLabel.ForeColor = 'Lime'
$outputLabel.Location = New-Object System.Drawing.Point(15, 185)
$form.Controls.Add($outputLabel)

# === Output Box ===
$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Multiline = $true
$outputBox.ScrollBars = "Vertical"
$outputBox.ReadOnly = $true
$outputBox.BackColor = 'Black'
$outputBox.ForeColor = 'Lime'
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$outputBox.BorderStyle = "FixedSingle"
$outputBox.Size = New-Object System.Drawing.Size(670, 250)
$outputBox.Location = New-Object System.Drawing.Point(15, 205)
$form.Controls.Add($outputBox)

# === Status Strip ===
$status = New-Object System.Windows.Forms.Label
$status.Dock = "Bottom"
$status.Height = 25
$status.BackColor = 'Black'
$status.ForeColor = 'DarkGray'
$status.TextAlign = "MiddleLeft"
$status.Padding = '10, 4, 0, 0'
$status.Text = "[ Ready for commands... ]"
$form.Controls.Add($status)

# === Run Logic ===
$runButton.Add_Click({
    $cmd = $inputBox.Text.Trim()

    if (![string]::IsNullOrWhiteSpace($cmd)) {
        $status.Text = "[ Running... ]"
        $form.Refresh()

        try {
            $result = Invoke-Expression $cmd 2>&1 | Out-String
            $outputBox.Text = $result
            $status.Text = "[ Done. ✅ ]"
        } catch {
            $outputBox.Text = "!! ERROR !!`r`n$($_.Exception.Message)"
            $status.Text = "[ Error occurred ❌ ]"
        }
    } else {
        $outputBox.Text = ">>> No command entered."
        $status.Text = "[ Idle... ]"
    }
})

# === Show Form ===
[void]$form.ShowDialog()
