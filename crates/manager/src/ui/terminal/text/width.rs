pub(super) fn shorten(value: &str, max: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    if UnicodeWidthStr::width(value) <= max {
        return value.into();
    }
    let mut output = String::new();
    for character in value.chars() {
        if UnicodeWidthStr::width(output.as_str())
            + unicode_width::UnicodeWidthChar::width(character).unwrap_or(0)
            + 1
            > max
        {
            break;
        }
        output.push(character);
    }
    output.push('…');
    output
}

pub(super) fn ellipsize(value: &str, width: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    if UnicodeWidthStr::width(value) <= width {
        return value.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let mut output = String::new();
    let mut used = 0;
    for character in value.chars() {
        let size = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + size + 1 > width {
            break;
        }
        output.push(character);
        used += size;
    }
    output.push('…');
    output
}
