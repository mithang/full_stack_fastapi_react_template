"use client";
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import {
    ColumnDef,
    flexRender,
    getCoreRowModel,
    useReactTable,
} from "@tanstack/react-table";
import { useEffect, useMemo, useState } from "react";
import {
    Pagination,
    PaginationContent,
    PaginationItem,
} from "@/components/ui/pagination";
import { Button } from "@/components/ui/button";
import {
    ChevronLeftIcon,
    ChevronRightIcon,
    ArrowLeftIcon,
    ArrowRightIcon
} from "lucide-react";
import { useSearchParams } from "react-router";
import { cn } from "@/lib/utils";
import type { IResponseData } from "@/components/shared/iresponse-data.inteface";
import { Loading } from "@/components/shared/loading";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, SelectGroup } from "@/components/ui/select";
import { IconFilter } from "@tabler/icons-react"
interface Props<T> {
    data: IResponseData<T>;
    columns: ColumnDef<T, any>[];
    hasBottomBorder?: boolean;
    loading?: boolean;
    errorMsg?: string;
    dropdownActions?: {
        options: Array<{ name: string; value: string }>;
    }
}

const DEFAULT_PAGE_LIMIT = 10;

export default function AdvanceTable<T>({
    data,
    columns,
    hasBottomBorder,
    loading,
    errorMsg,
    dropdownActions
}: Props<T>) {

    const [searchParams, setSearchParams] = useSearchParams();
    function onDropdownChange(value: string) {
        searchParams.set("action", value);
        if (value === "all") {
            searchParams.delete("action");
        }
        // A new filter starts a new result set, so drop the page offset:
        // keeping ?skip= from the old filter could land past the end of
        // the filtered results and show an empty table even though
        // matching records exist on page 1. All table providers already
        // default a missing skip to 0, and the page sync effect below
        // follows the URL back to page 1.
        searchParams.delete("skip");
        setSearchParams(searchParams);
    }
    const pageLimit = useMemo(
        () => Number(searchParams.get("limit")),
        [searchParams],
    );

    const selectedAction = useMemo(
        () => searchParams.get("action") || "all",
        [searchParams],
    );

    // Guard the limit the same way skip is guarded (|| 0 above): a
    // non-numeric or negative ?limit= (hand-edited URL, stale bookmark)
    // previously propagated as NaN/negative through totalPage, currentPage
    // and pageSize, breaking the "Page X of Y" label. A missing limit
    // still reads as 0 and falls back to the default, as before.
    const limit = Number.isFinite(pageLimit) && pageLimit > 0 ? pageLimit : DEFAULT_PAGE_LIMIT;

    // The backend treats ?skip= as a record offset (Mongo .skip(), and the
    // audit-log slice newest_first[skip:skip+limit]), not a page number, so
    // the page index derived from the URL is skip / limit. Previously the
    // raw skip value was used as the page index, and the effect below wrote
    // the page index back as skip — so "Page 2" fetched offset 1 instead of
    // offset limit, showing almost the same rows as page 1.
    const currentPage = useMemo(
        () => Math.max(0, Math.floor((Number(searchParams.get("skip")) || 0) / limit)),
        [searchParams, limit],
    );

    const { items, total } = data;
    const totalPage = Math.ceil(total / limit);
    const [pagination, setPagination] = useState<{
        pageIndex: number;
        pageSize: number;
    }>({
        pageIndex: currentPage,
        pageSize: limit,
    });
    const table = useReactTable<T>({
        data: items,
        columns,
        getCoreRowModel: getCoreRowModel(),
        manualPagination: true,
        pageCount: totalPage,
        onPaginationChange: setPagination,
        state: {
            pagination,
        },
    });

    useEffect(() => {
        // Also normalise a skip that is not a page boundary: the page
        // index is floor(skip / limit), but the providers fetch the raw
        // skip, so ?skip=15&limit=10 labelled "Page 2" while showing
        // records 16-25 instead of page 2's 11-20 (and next/prev then
        // jumped by a full page from that misaligned offset). Rewriting
        // the URL to the page's own offset makes the providers refetch
        // the records the label promises; a non-numeric or negative skip
        // is normalised the same way, since it never equals a page offset
        // (missing skip reads as 0, which is page 0's offset, so normal
        // navigation writes nothing extra). The rewrite lands on an
        // already-agreeing skip, so this cannot ping-pong. The effect
        // deliberately still runs only on pageIndex changes, so it
        // cannot fight the back/forward sync effect below; a same-page
        // URL edit to another misaligned skip therefore normalises on
        // the next page change, not immediately.
        const rawSkip = Number(searchParams.get("skip"));
        if (pagination.pageIndex !== currentPage || rawSkip !== pagination.pageIndex * limit) {
            // Write a record offset, not the page index: page N starts at
            // record N * limit (see the currentPage derivation above).
            const skip = (pagination.pageIndex * limit).toString();
            if (searchParams.get("action") && dropdownActions) {
                setSearchParams({ 'skip': skip, 'limit': limit.toString(), 'action': searchParams.get("action")! });
            }
            else {
                setSearchParams({ 'skip': skip, 'limit': limit.toString() });
            }
        }
    }, [pagination.pageIndex]);

    // Sync the page back from the URL: browser back/forward changes ?skip=
    // and the providers refetch that page, but pagination state was only
    // initialised from the URL once, so the "Page X of Y" label and the
    // prev/next buttons kept the old page — a displayed-vs-applied
    // mismatch in the same class as the action-filter fix. This effect
    // runs only when the URL page changes (not on pagination clicks, so
    // it cannot fight the effect above), and the functional updater makes
    // it a no-op once the two agree, so the two directions cannot
    // ping-pong: a click pushes the URL, then this sees them equal.
    useEffect(() => {
        setPagination((prev) => prev.pageIndex === currentPage ? prev : { ...prev, pageIndex: currentPage });
    }, [currentPage]);

    // Normalise a misaligned skip edited in place: the pagination -> URL
    // effect above only runs on pageIndex changes, so a same-page URL edit
    // (e.g. ?skip=10 -> ?skip=15 on page 2) left the providers fetching
    // the raw offset while the label promised page 2's records, until the
    // next page change. This effect runs on URL changes but only acts
    // once pagination already agrees with the URL page (i.e. after the
    // sync effect above has settled), so it cannot fight back/forward
    // navigation the way an unguarded URL-keyed rewrite would: while the
    // two disagree it stays out, and once they agree a misaligned skip is
    // rewritten to the page's own offset and the providers refetch the
    // records the label promises. A rewrite lands on an agreeing skip, so
    // it cannot ping-pong.
    useEffect(() => {
        const rawSkip = Number(searchParams.get("skip"));
        if (pagination.pageIndex === currentPage && rawSkip !== pagination.pageIndex * limit) {
            const skip = (pagination.pageIndex * limit).toString();
            if (searchParams.get("action") && dropdownActions) {
                setSearchParams({ 'skip': skip, 'limit': limit.toString(), 'action': searchParams.get("action")! });
            }
            else {
                setSearchParams({ 'skip': skip, 'limit': limit.toString() });
            }
        }
    }, [searchParams, pagination.pageIndex, currentPage]);

    // Clamp a page index that runs past the last page: a hand-edited or
    // stale-bookmark ?skip= beyond total (or a total that shrank since the
    // URL was saved) otherwise fetched an empty page and showed a blank
    // table labelled e.g. "Page 101 of 3" — renderEmptyState only covers
    // the total == 0 case, so nothing explained the empty table, and the
    // label itself was out of range. The pagination -> URL effect above
    // then writes the clamped page's offset, so the URL follows and the
    // two directions settle; totalPage == 0 (no records yet) is left
    // alone so the initial load is not clamped to page -1.
    useEffect(() => {
        if (totalPage > 0 && pagination.pageIndex >= totalPage) {
            setPagination((prev) => ({ ...prev, pageIndex: totalPage - 1 }));
        }
    }, [totalPage, pagination.pageIndex]);

    const showPagination = items.length < total;
    const renderEmptyState = () => {
        if (items.length === 0 && total === 0 && !loading) {
            return (
                <div className="grid place-items-center place-content-center h-40">
                    {errorMsg ? errorMsg : "No Records"}
                </div>
            );
        }
        if (loading) {
            return (
                <div className="grid place-items-center place-content-center h-40">
                    <Loading variant="dots" size="md" text="Loading data..." />
                </div>
            );
        }
        return <></>;
    };

    return (
        <div className="shadow max-w-[calc(100vw-1rem)] md:max-w-full overflow-hidden rounded-md border">
            {dropdownActions && (
                <div className="p-4 flex justify-end">
                    <Select onValueChange={onDropdownChange} value={selectedAction}>
                        <SelectTrigger className="w-[180px] ">
                            <IconFilter className="w-4 h-4" />
                            <SelectValue placeholder="Actions" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectGroup>
                                {dropdownActions.options.map((option) => (
                                    <SelectItem key={option.value} value={option.value}>
                                        {option.name}
                                    </SelectItem>
                                ))}
                                <SelectItem value="all">All</SelectItem>
                            </SelectGroup>
                        </SelectContent>
                    </Select>
                </div>
            )}
            <Table>
                <TableHeader>
                    {table.getHeaderGroups().map((headerGroup) => {
                        return (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map((header) => {
                                    return (
                                        <TableHead key={header.id}>
                                            <span className="block truncate">
                                                {header.isPlaceholder
                                                    ? null
                                                    : flexRender(
                                                        header.column.columnDef.header,
                                                        header.getContext(),
                                                    )}
                                            </span>
                                        </TableHead>
                                    );
                                })}
                            </TableRow>
                        );
                    })}
                </TableHeader>
                <TableBody>
                    {table.getRowModel().rows.map((row) => {
                        if (loading) return null;
                        return (
                            <TableRow
                                key={row.id}
                                className={cn({
                                    "border-b": hasBottomBorder,
                                })}
                            >
                                {row.getVisibleCells().map((cell) => {
                                    return (
                                        <TableCell key={cell.id}>
                                            <span className="block truncate">
                                                {flexRender(
                                                    cell.column.columnDef.cell,
                                                    cell.getContext(),
                                                )}
                                            </span>
                                        </TableCell>
                                    );
                                })}
                            </TableRow>
                        );
                    })}
                </TableBody>
            </Table>
            {renderEmptyState()}
            {showPagination && (
                <div className="pt-3 pb-3">
                    <Pagination>
                        <PaginationContent>
                            <PaginationItem>
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => table.firstPage()}
                                    disabled={!table.getCanPreviousPage()}
                                    aria-disabled={!table.getCanPreviousPage()}
                                >
                                    <ArrowLeftIcon />
                                </Button>
                            </PaginationItem>
                            <PaginationItem>
                                <Button
                                    size="icon"
                                    variant="outline"
                                    onClick={() => table.previousPage()}
                                    disabled={!table.getCanPreviousPage()}
                                    aria-disabled={!table.getCanPreviousPage()}
                                >
                                    <ChevronLeftIcon />
                                </Button>
                            </PaginationItem>
                            <PaginationItem>
                                <span className="flex pl-2 pr-2 text-sm">
                                    Page {pagination.pageIndex + 1} of {totalPage}
                                </span>
                            </PaginationItem>
                            <PaginationItem>
                                <Button
                                    size="icon"
                                    variant="outline"
                                    onClick={() => table.nextPage()}
                                    disabled={!table.getCanNextPage()}
                                    aria-disabled={!table.getCanNextPage()}
                                >
                                    <ChevronRightIcon />
                                </Button>
                            </PaginationItem>
                            <PaginationItem>
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => table.lastPage()}
                                    disabled={!table.getCanNextPage()}
                                    aria-disabled={!table.getCanNextPage()}
                                >
                                    <ArrowRightIcon />
                                </Button>
                            </PaginationItem>
                        </PaginationContent>
                    </Pagination>
                </div>
            )}
        </div>
    );
}