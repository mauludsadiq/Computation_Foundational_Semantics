#[derive(Clone)]
pub struct Test<E> {
    pub id_norm: String, // ASC7-normalized label
    pub f: fn(&E) -> bool,
}

#[derive(Clone)]
pub struct TestFamily<E> {
    pub tests: Vec<Test<E>>,
}

impl<E> TestFamily<E> {
    pub fn new(tests: Vec<Test<E>>) -> Self { Self { tests } }

    pub fn signature(&self, x: &E) -> Vec<bool> {
        self.tests.iter().map(|t| (t.f)(x)).collect()
    }
}
