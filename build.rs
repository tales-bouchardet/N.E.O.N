fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        // Use seu caminho real do ícone:
        res.set_icon("assets/icon.ico");
        res.compile().expect("Falha ao compilar recursos");
    }
}