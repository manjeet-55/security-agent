import type { ProjectStatus } from './status.js';

export type HomeAction = 'fixes' | 'scan' | 'report' | 'checklist' | 'collector' | 'risks' | 'verify' | 'lessons' | 'ai' | 'settings' | 'help' | 'exit';

export interface Suggestion {
  action: HomeAction;
  /** What I noticed and why it is the next step, in a sentence or two. */
  text: string;
  /** The server a collector suggestion is about. */
  host?: string;
}

const OLD_SCAN_DAYS = 7;
const ENDING_SOON_DAYS = 7;

/** The next step, by fixed rules in order (spec §4.2): the same status always gives the same suggestion. */
export function suggestNext(s: ProjectStatus): Suggestion {
  const scan = s.lastScan;
  if (!scan) return { action: 'scan', text: 'This project has not been scanned yet. Let me run the first scan.' };
  const server = s.servers.find((h) => h.collector !== 'fresh');
  if (server) {
    const state = server.collector === 'none' ? 'has no collector output yet' : 'has collector output older than 7 days';
    return { action: 'collector', host: server.name, text: `${server.name} ${state}, so I cannot check its SSH, nginx or packages. Add it next.` };
  }
  if (scan.urgent > 0) return { action: 'fixes', text: `${scan.urgent} high-priority issue(s) are open. Fix those first; I will show you what to change.` };
  const ending = s.accepted.find((a) => a.daysLeft <= ENDING_SOON_DAYS);
  if (ending) {
    const when = ending.daysLeft === 0 ? 'today' : `in ${ending.daysLeft} day(s)`;
    return { action: 'risks', text: `The accepted risk on ${ending.findingId} ends ${when}; after that it counts as open again.` };
  }
  if (s.unscanned.length > 0) {
    const one = s.unscanned.length === 1;
    return { action: 'scan', text: `${s.unscanned.join(', ')} ${one ? 'has' : 'have'} not been scanned yet. Scan again to include ${one ? 'it' : 'them'}.` };
  }
  if (scan.ageDays > OLD_SCAN_DAYS) return { action: 'scan', text: `The last scan is ${scan.ageDays} days old. Scan again to see where things stand now.` };
  if (!s.checklistExported) {
    return { action: 'checklist', text: 'The scan cannot see everything: routes without a login check, unsafe queries, cloud settings. The review checklist covers those.' };
  }
  return { action: 'scan', text: 'Nothing pressing. Scan again after your next deploy.' };
}
