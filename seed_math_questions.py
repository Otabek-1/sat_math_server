import hashlib
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def mcq(prompt, choices, answer, explanation):
    return {
        "kind": "mcq",
        "section": "math",
        "prompt": prompt,
        "choices": choices,
        "answer": answer,
        "explanation": explanation,
    }


def spr(prompt, answer, explanation):
    return {
        "kind": "spr",
        "section": "math",
        "prompt": prompt,
        "choices": [],
        "answer": answer,
        "explanation": explanation,
    }


QUESTIONS = [
    mcq("If $x+7=12$, what is $x$?", ["3", "4", "5", "6"], "5", "Subtract 7 from both sides: $x=12-7=5$."),
    mcq("What is $25\\%$ of $80$?", ["20", "25", "30", "40"], "20", "$0.25\\times80=20$."),
    mcq("If $3x=21$, what is $x$?", ["6", "7", "8", "9"], "7", "Divide both sides by 3: $x=7$."),
    mcq("What is $7^2-4^2$?", ["33", "45", "49", "65"], "33", "$49-16=33$."),
    mcq("A line passes through $(2,3)$ and $(4,7)$. What is its slope?", ["1", "2", "3", "4"], "2", "Slope is $(7-3)/(4-2)=4/2=2$."),
    mcq("Which fraction is equivalent to $0.6$?", ["$1/2$", "$2/3$", "$3/5$", "$5/3$"], "$3/5$", "$0.6=6/10=3/5$."),
    mcq("What is $|-9|+|-4|$?", ["5", "13", "36", "52"], "13", "Absolute values are 9 and 4, so $9+4=13$."),
    mcq("If $y=2x+1$ and $x=4$, what is $y$?", ["7", "8", "9", "10"], "9", "Substitute $x=4$: $y=2(4)+1=9$."),
    mcq("What is the area of a rectangle with length 12 and width 5?", ["17", "34", "60", "120"], "60", "Area is length times width: $12\\times5=60$."),
    mcq("Which expression equals $3(x+4)$?", ["$3x+4$", "$3x+12$", "$x+12$", "$7x$"], "$3x+12$", "Distribute 3 across $(x+4)$."),
    mcq("What is $15-3\\times4$?", ["3", "12", "48", "52"], "3", "Use order of operations: $15-12=3$."),
    mcq("If $2a+3=13$, what is $a$?", ["4", "5", "6", "8"], "5", "$2a=10$, so $a=5$."),
    mcq("What is the median of $2,8,5,7,3$?", ["3", "5", "7", "8"], "5", "The ordered list is $2,3,5,7,8$, whose middle value is 5."),
    mcq("Which value is a solution of $x^2=16$?", ["-8", "-4", "2", "8"], "-4", "Both $4$ and $-4$ satisfy $x^2=16$; only $-4$ is listed."),
    mcq("The ratio of boys to girls is $3:5$. If there are 24 boys, how many girls are there?", ["32", "40", "45", "48"], "40", "The scale factor is $24/3=8$, so girls equal $5\\times8=40$."),
    mcq("What is $\\sqrt{144}$?", ["10", "11", "12", "14"], "12", "$12^2=144$."),
    mcq("A price of $50 is increased by 20%. What is the new price?", ["55", "60", "70", "100"], "60", "$50+0.20(50)=60$."),
    mcq("Which angle pair is supplementary?", ["$30^\\circ$ and $50^\\circ$", "$45^\\circ$ and $45^\\circ$", "$60^\\circ$ and $120^\\circ$", "$90^\\circ$ and $100^\\circ$"], "$60^\\circ$ and $120^\\circ$", "Supplementary angles have a sum of $180^\\circ$."),
    mcq("What is $(x+3)(x-3)$?", ["$x^2-9$", "$x^2+9$", "$x^2-6x+9$", "$x^2+6x+9$"], "$x^2-9$", "Use the difference-of-squares identity."),
    mcq("If $f(x)=x^2+2x$, what is $f(3)$?", ["9", "12", "15", "21"], "15", "$f(3)=9+6=15$."),
    mcq("A bag has 3 red, 2 blue, and 5 green balls. What is the probability of red?", ["$1/10$", "$3/10$", "$1/3$", "$3/7$"], "$3/10$", "There are 3 red balls among 10 total."),
    mcq("What is $5/8+1/4$?", ["$6/12$", "$7/8$", "$3/4$", "$8/12$"], "$7/8$", "$1/4=2/8$, so $5/8+2/8=7/8$."),
    mcq("The product of $-6$ and $-5$ is:", ["-30", "-11", "11", "30"], "30", "The product of two negative numbers is positive."),
    mcq("If $g(x)=4x-7$, for what $x$ does $g(x)=9$?", ["2", "4", "5", "16"], "4", "$4x-7=9$, so $4x=16$ and $x=4$."),
    mcq(r"What is the circumference of a circle with radius 3? Use $\pi$", [r"$3\pi$", r"$6\pi$", r"$9\pi$", r"$18\pi$"], r"$6\pi$", r"Circumference is $2\pi r=2\pi(3)=6\pi$."),

    spr("Solve $x-8=15$.", "23", "Add 8 to both sides."),
    spr("Evaluate $4^3$.", "64", "$4^3=4\\times4\\times4=64$."),
    spr("What is $12+18-7$?", "23", "$12+18=30$, then $30-7=23$."),
    spr("A triangle has sides 6, 8, and 10. What is its area?", "24", "This is a $6$-$8$-$10$ right triangle, so area is $(6\\times8)/2=24$."),
    spr("Solve $5x+10=35$.", "5", "$5x=25$, so $x=5$."),
    spr("What is $30\\%$ of $150$?", "45", "$0.30\\times150=45$."),
    spr("Find the next term: $3,7,11,15,\u2026$", "19", "The sequence adds 4 each term."),
    spr("What is the perimeter of a square with side length 9?", "36", "Perimeter is $4\\times9=36$."),
    spr("Simplify $2^3\\times2^4$.", "128", "$2^{3+4}=2^7=128$."),
    spr("If $q=3$, what is $q^3+q^2$?", "36", "$27+9=36$."),
    spr("A line has equation $y=5x-2$. What is the $y$-intercept?", "-2", "In $y=mx+b$, the intercept is $b=-2$."),
    spr("Solve $2(x-3)=10$.", "8", "Divide by 2: $x-3=5$, so $x=8$."),
    spr("What is $\\frac{3}{4}$ of $40$?", "30", "$40\\times3/4=30$."),
    spr("How many degrees are in the sum of a triangle's interior angles?", "180", "Triangle interior angles sum to $180^\\circ$."),
    spr("Find $x$ if $x/6=7$.", "42", "Multiply both sides by 6."),
    spr("What is the range of $4,9,2,11,6$?", "9", "$11-2=9$."),
    spr("Evaluate $\\sqrt{49}+\\sqrt{36}$.", "13", "$7+6=13$."),
    spr("A notebook costs $3 and a pen costs $2. How much do 4 notebooks and 3 pens cost?", "18", "$4(3)+3(2)=12+6=18$."),
    spr("Solve $x^2-9=0$ for the positive solution.", "3", "$x^2=9$, so the positive solution is 3."),
    spr("What is $5!$?", "120", "$5!=5\\times4\\times3\\times2\\times1=120$."),
    spr("Find the mean of $6,8,10,12$.", "9", "The sum is 36, divided by 4 gives 9."),
    spr("A 10% discount is applied to $80. What is the discount amount?", "8", "$0.10\\times80=8$."),
    spr("If $r=2$ and $h=5$, find the volume of a cylinder $\\pi r^2h$.", "$20\\pi$", "$\\pi(2^2)(5)=20\\pi$."),
    spr("Simplify $\\frac{18}{24}$.", "$3/4$", "Divide numerator and denominator by 6."),
    spr("If $a+b=10$ and $a-b=4$, what is $a$?", "7", "Adding the equations gives $2a=14$, so $a=7$."),
]


def fingerprint(question):
    canonical = {
        "kind": question["kind"],
        "section": question["section"],
        "prompt": " ".join(question["prompt"].split()),
        "choices": question["choices"],
        "answer": question["answer"].strip().casefold(),
        "explanation": " ".join(question["explanation"].split()),
        "image_url": None,
        "taxonomy_id": None,
    }
    return hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()


def main():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")

    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT NOT NULL DEFAULT 'medium'"))
        connection.execute(text("ALTER TABLE questions DROP CONSTRAINT IF EXISTS questions_difficulty_check"))
        connection.execute(text("ALTER TABLE questions ADD CONSTRAINT questions_difficulty_check CHECK(difficulty IN ('easy','medium','hard'))"))
        owner = connection.execute(
            text("""
                SELECT id FROM users
                WHERE role IN ('super_admin', 'admin', 'teacher')
                ORDER BY CASE role
                    WHEN 'super_admin' THEN 1
                    WHEN 'admin' THEN 2
                    WHEN 'teacher' THEN 3
                END, created_at
                LIMIT 1
            """)
        ).first()
        if not owner:
            raise RuntimeError("No staff user is available to own the seeded questions")

        taxonomies = [
            ("math", "Algebra", "Linear equations"),
            ("math", "Advanced Math", "Quadratic and polynomial expressions"),
            ("math", "Problem-Solving", "Ratios, percentages, and probability"),
            ("math", "Geometry", "Area, perimeter, volume, and angles"),
            ("math", "Statistics", "Mean, median, range, and distributions"),
        ]
        taxonomy_ids = []
        for domain, skill in [(domain_skill[1], domain_skill[2]) for domain_skill in taxonomies]:
            row = connection.execute(
                text("""
                    INSERT INTO taxonomies(section,domain,skill,created_by)
                    VALUES ('math',:domain,:skill,CAST(:owner AS UUID))
                    ON CONFLICT(section,domain,skill) DO UPDATE SET skill=EXCLUDED.skill
                    RETURNING id
                """),
                {"domain": domain, "skill": skill, "owner": str(owner[0])},
            ).first()
            taxonomy_ids.append(str(row[0]))

        inserted = 0
        skipped = 0
        for index, question in enumerate(QUESTIONS):
            question_hash = fingerprint(question)
            difficulty = "easy" if index < 17 else "medium" if index < 34 else "hard"
            taxonomy_id = taxonomy_ids[index % len(taxonomy_ids)]
            exists = connection.execute(
                text("""
                    SELECT 1 FROM questions
                    WHERE owner_id = CAST(:owner AS UUID)
                      AND content_hash = :fingerprint
                    LIMIT 1
                """),
                {"owner": str(owner[0]), "fingerprint": question_hash},
            ).first()
            if exists:
                skipped += 1
                connection.execute(
                    text("""
                        UPDATE questions
                        SET difficulty=:difficulty,
                            taxonomy_id=CAST(:taxonomy AS UUID),
                            updated_at=NOW()
                        WHERE owner_id=CAST(:owner AS UUID)
                          AND content_hash=:fingerprint
                    """),
                    {
                        "owner": str(owner[0]),
                        "fingerprint": question_hash,
                        "difficulty": difficulty,
                        "taxonomy": taxonomy_id,
                    },
                )
                continue

            result = connection.execute(
                text("""
                    INSERT INTO questions (
                        owner_id, kind, section, prompt, choices, answer,
                        explanation, image_url, taxonomy_id, difficulty, content_hash
                    )
                    VALUES (
                        CAST(:owner AS UUID), :kind, :section, :prompt,
                        CAST(:choices AS JSONB), :answer, :explanation,
                        NULL, CAST(:taxonomy AS UUID), :difficulty, :fingerprint
                    )
                """),
                {
                    "owner": str(owner[0]),
                    "kind": question["kind"],
                    "section": question["section"],
                    "prompt": question["prompt"],
                    "choices": json.dumps(question["choices"]),
                    "answer": question["answer"].strip(),
                    "explanation": question["explanation"],
                    "fingerprint": question_hash,
                    "taxonomy": taxonomy_id,
                    "difficulty": difficulty,
                },
            )
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1

    print(f"Seeded Math questions: inserted={inserted}, skipped_existing={skipped}, total={len(QUESTIONS)}")


if __name__ == "__main__":
    main()
