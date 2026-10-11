function encodePathSegment(segment) {
  return encodeURIComponent(segment).replaceAll('%3A', ':');
}

function escapeGoPath(path) {
  return path
    .split('/')
    .map((part) => [...part].map((char) => {
      if (char >= 'A' && char <= 'Z') return `!${char.toLowerCase()}`;
      return char;
    }).join(''))
    .join('/');
}

export function packagePurlName(ecosystem, name) {
  const type = ecosystem === 'Go' ? 'golang' : ecosystem.toLowerCase();
  const normalizedName = ecosystem === 'Go' ? escapeGoPath(name) : name;
  const encodedName = normalizedName.split('/').map(encodePathSegment).join('/');
  return `pkg:${type}/${encodedName}`;
}

export function createPurl(ecosystem, name, version) {
  return `${packagePurlName(ecosystem, name)}@${encodeURIComponent(version)}`;
}
