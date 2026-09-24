use super::*;

pub(super) fn execute_bulk(
    controller: &mut Controller,
    paths: Vec<String>,
    kind: GenerateKind,
    outgoing: &Sender<Event>,
) -> Completion {
    let total = paths.len();
    let mut saved = 0;
    let mut failed = Vec::new();
    for (index, path) in paths.into_iter().enumerate() {
        match controller.generate_missing_password(&path, kind) {
            Ok(()) => saved += 1,
            Err(error) => failed.push(format!("{path}: {error}")),
        }
        if outgoing
            .send(Event::Completion(Completion::BulkProgress {
                done: index + 1,
                total,
            }))
            .is_err()
        {
            break;
        }
    }
    Completion::BulkGenerated { saved, failed }
}
