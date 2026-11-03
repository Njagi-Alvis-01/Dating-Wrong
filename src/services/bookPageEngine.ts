import { ChapterSection, BookPage, BookMetadata } from '../types.ts';
import { ALL_BOOK_PAGES } from '../data/manuscript/allPages.ts';

/**
 * High Quality Book Page Rendering Engine
 * Transforms manuscript sections into the exact 122 physical book pages matching the PDF.
 * Preserves typography, chapter headings, Bible quotations, epigraphs, and page layout.
 * Strictly adheres to Section 31: NO PERSONALIZED WATERMARKS.
 */
export function generateBookPages(
  _metadata: BookMetadata,
  sections: ChapterSection[]
): BookPage[] {
  // If only preview sections requested
  if (sections.length < 7) {
    const requestedIds = new Set(sections.map((s) => s.id));
    return ALL_BOOK_PAGES.filter(
      (p) => requestedIds.has(p.sectionId) || p.sectionId === 'title-page' || p.sectionId === 'contents'
    );
  }

  // Complete official 122-page book
  return ALL_BOOK_PAGES;
}
