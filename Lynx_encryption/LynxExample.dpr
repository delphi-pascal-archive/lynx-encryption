program LynxExample;

uses
  Forms,
  Main in 'Main.pas' {MainForm},
  Lynx in 'Lynx.pas',
  MD5Api in 'MD5Api.pas',
  MD5Core in 'MD5Core.pas';

{$R *.res}
{$R WinThemes.res}

begin
  Application.Initialize;
  Application.Title := 'Chiffrement Lynx';
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
