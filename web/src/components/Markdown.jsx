import React from 'react';

function renderInline(text, keyPrefix = 'i') {
  if (text == null || text === '') return null;
  const chunks = String(text).split(/(`[^`\n]*`)/);
  return chunks.map((chunk, i) => {
    const key = `${keyPrefix}-${i}`;
    if (chunk.startsWith('`') && chunk.endsWith('`') && chunk.length >= 2) {
      return <code key={key}>{chunk.slice(1, -1)}</code>;
    }
    const parts = chunk.split(/(\*\*[^*]+?\*\*)/);
    return parts.map((part, j) => {
      const k = `${key}-${j}`;
      if (part.startsWith('**') && part.endsWith('**') && part.length >= 4) {
        return <strong key={k}>{part.slice(2, -2)}</strong>;
      }
      return part;
    });
  });
}

function CodeBlock({ lang, text }) {
  const lines = String(text || '').split('\n');
  return (
    <pre className={`md-code${lang ? ` lang-${lang}` : ''}`}>
      {lang ? <span className="md-lang">{lang}</span> : null}
      {lang === 'diff'
        ? lines.map((line, i) => (
            <span
              key={i}
              className={
                line.startsWith('+') ? 'diff-add' : line.startsWith('-') ? 'diff-del' : undefined
              }
            >
              {line}
              {i < lines.length - 1 ? '\n' : ''}
            </span>
          ))
        : <code>{text}</code>}
    </pre>
  );
}

function parseBlocks(src) {
  const lines = String(src || '').replace(/\r\n/g, '\n').split('\n');
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (/^```/.test(line)) {
      const lang = line.slice(3).trim().split(/\s+/)[0] || '';
      const code = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) {
        code.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) i += 1;
      blocks.push({ type: 'code', lang, text: code.join('\n') });
      continue;
    }

    if (/^\s*$/.test(line)) {
      i += 1;
      continue;
    }

    if (/^(-{3,}|\*{3,})\s*$/.test(line)) {
      blocks.push({ type: 'hr' });
      i += 1;
      continue;
    }

    const heading = /^(#{1,3})\s+(.+)$/.exec(line);
    if (heading) {
      blocks.push({ type: 'heading', level: heading[1].length, text: heading[2] });
      i += 1;
      continue;
    }

    if (/^>\s?/.test(line)) {
      const quoted = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        quoted.push(lines[i].replace(/^>\s?/, ''));
        i += 1;
      }
      blocks.push({ type: 'quote', text: quoted.join('\n') });
      continue;
    }

    const ordered = /^\d+\.\s+/.test(line);
    const unordered = /^[-*]\s+/.test(line);
    if (ordered || unordered) {
      const itemRe = ordered ? /^(\d+)\.\s+(.*)$/ : /^[-*]\s+(.*)$/;
      const items = [];
      while (i < lines.length) {
        const current = lines[i];
        const start = itemRe.exec(current);
        if (start) {
          const chunks = [start[start.length - 1]];
          i += 1;
          while (i < lines.length) {
            const next = lines[i];
            if (/^\s*$/.test(next)) break;
            if (itemRe.test(next)) break;
            if (/^```/.test(next) || /^#{1,3}\s+/.test(next) || /^(-{3,}|\*{3,})\s*$/.test(next)) break;
            if (/^( {2,}|\t)/.test(next)) {
              chunks.push(next.replace(/^( {2,}|\t)/, ''));
              i += 1;
              continue;
            }
            break;
          }
          items.push(chunks.join('\n'));
          continue;
        }
        if (
          /^\s*$/.test(current)
          && i + 1 < lines.length
          && itemRe.test(lines[i + 1])
        ) {
          i += 1;
          continue;
        }
        break;
      }
      blocks.push({ type: ordered ? 'ol' : 'ul', items });
      continue;
    }

    const para = [line];
    i += 1;
    while (i < lines.length) {
      const next = lines[i];
      if (/^\s*$/.test(next)) break;
      if (/^```/.test(next) || /^#{1,3}\s+/.test(next) || /^(-{3,}|\*{3,})\s*$/.test(next)) break;
      if (/^>\s?/.test(next) || /^\d+\.\s+/.test(next) || /^[-*]\s+/.test(next)) break;
      para.push(next);
      i += 1;
    }
    blocks.push({ type: 'p', text: para.join(' ') });
  }

  return blocks;
}

function ListItem({ text, index }) {
  const lines = String(text || '').split('\n');
  const first = lines[0] || '';
  const rest = lines.slice(1).join('\n').trim();
  return (
    <li>
      {renderInline(first, `li-${index}`)}
      {rest ? <Markdown text={rest} /> : null}
    </li>
  );
}

export function Markdown({ text }) {
  if (!text) return null;
  const blocks = parseBlocks(text);
  return (
    <div className="md">
      {blocks.map((block, i) => {
        if (block.type === 'heading') {
          const Tag = block.level === 1 ? 'h3' : block.level === 2 ? 'h3' : 'h4';
          return <Tag key={i}>{renderInline(block.text, `h-${i}`)}</Tag>;
        }
        if (block.type === 'code') {
          return <CodeBlock key={i} lang={block.lang} text={block.text} />;
        }
        if (block.type === 'hr') return <hr key={i} />;
        if (block.type === 'quote') {
          return <blockquote key={i}>{renderInline(block.text, `q-${i}`)}</blockquote>;
        }
        if (block.type === 'ol' || block.type === 'ul') {
          const Tag = block.type === 'ol' ? 'ol' : 'ul';
          return (
            <Tag key={i}>
              {block.items.map((item, j) => (
                <ListItem key={j} text={item} index={`${i}-${j}`} />
              ))}
            </Tag>
          );
        }
        return <p key={i}>{renderInline(block.text, `p-${i}`)}</p>;
      })}
    </div>
  );
}
